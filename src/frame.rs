//! Frame reading and writing. A frame is `[u32 big-endian length][nonce
//! || ciphertext || tag]`; the length prefix is what makes the stream
//! parseable without knowing anything about the plaintext, which is the
//! whole point: the server splits an encrypted stream into database rows
//! without ever holding a key.
//!
//! Frames are stored without their prefix (one row per frame) and the
//! prefix is re-added on download, so what the downloader receives is
//! byte-identical to what the uploader sent.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Stream, StreamExt};
use std::{fmt, marker::PhantomData};

use crate::crypto::{CHUNK_PLAINTEXT, META_PLAINTEXT_LIMIT, NONCE_LEN, TAG_LEN};

/// What can go wrong while reading frames off a stream.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("malformed upload: {0}")]
    Malformed(String),
    #[error("upload exceeds the configured limit of {0} bytes")]
    TooLarge(u64),
    #[error("upload stream failed: {0}")]
    Io(String),
}

/// The first frame is the ML-KEM-1024 ciphertext: exactly
/// `crate::crypto::KEM_CT_LEN` bytes, enforced as a range here and as an
/// exact length by the writer that finishes the stream.
pub fn max_kem_ct() -> usize {
    crate::crypto::KEM_CT_LEN
}

/// The second frame carries the metadata chunk, which has its own (much
/// smaller) size limit.
pub fn max_meta_ct() -> usize {
    META_PLAINTEXT_LIMIT + NONCE_LEN + TAG_LEN
}

pub fn max_chunk_ct() -> usize {
    CHUNK_PLAINTEXT + NONCE_LEN + TAG_LEN
}

/// The smallest legal frame: an empty plaintext still has a nonce and a tag.
pub fn empty_frame_ct() -> usize {
    NONCE_LEN + TAG_LEN
}

/// Write one frame (length prefix + data) into `out`.
pub fn put_frame(out: &mut BytesMut, data: &[u8]) {
    out.put_u32(u32::try_from(data.len()).unwrap_or(u32::MAX));
    out.put_slice(data);
}

/// Incremental frame reader over a byte stream. Validates every frame as it
/// arrives: the first against the metadata limit, the rest against the data
/// chunk limit, the running total against the upload cap.
pub struct FrameReader<S, E> {
    stream: S,
    buf: BytesMut,
    frames: u32,
    stored_ct: u64,
    cap: u64,
    _error: PhantomData<E>,
}

impl<S, E> FrameReader<S, E>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: fmt::Display,
{
    pub fn new(stream: S, cap: u64) -> Self {
        Self {
            stream,
            buf: BytesMut::new(),
            frames: 0,
            stored_ct: 0,
            cap,
            _error: PhantomData,
        }
    }

    /// Next validated frame, or `None` at a clean end of stream. Position
    /// matters: frame 0 is the ML-KEM-1024 ciphertext, frame 1 the metadata
    /// chunk, everything after a data chunk. A stream that stops mid-frame
    /// is an error, not a short share: a downloader would otherwise have
    /// to guess whether the tail is missing.
    pub async fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        loop {
            // BytesMut is always one contiguous buffer, so chunk() is the
            // whole unread part and the length checks below are the only
            // guards the slicing needs.
            if let Some((prefix, _)) = self.buf.chunk().split_first_chunk::<4>() {
                let len = u32::from_be_bytes(*prefix);
                let (max, which) = match self.frames {
                    0 => (max_kem_ct(), "encapsulation"),
                    1 => (max_meta_ct(), "metadata"),
                    _ => (max_chunk_ct(), "data"),
                };
                let Some(len) = usize::try_from(len)
                    .ok()
                    .filter(|len| *len >= empty_frame_ct())
                else {
                    return Err(FrameError::Malformed(
                        "a frame must carry at least a nonce and a tag (28 bytes)".into(),
                    ));
                };
                if len > max {
                    return Err(FrameError::Malformed(format!(
                        "the {which} frame is larger than the format allows ({len} > {max} bytes)"
                    )));
                }
                if self.buf.remaining() >= 4 + len {
                    self.buf.advance(4);
                    let frame = self.buf.split_to(len).to_vec();
                    self.frames += 1;
                    self.stored_ct += u64::from(4_u32) + len as u64;
                    if self.stored_ct > self.cap {
                        return Err(FrameError::TooLarge(self.cap));
                    }
                    return Ok(Some(frame));
                }
            }
            match self.stream.next().await {
                Some(Ok(chunk)) => self.buf.extend_from_slice(&chunk),
                Some(Err(error)) => return Err(FrameError::Io(error.to_string())),
                None => {
                    if self.buf.has_remaining() {
                        return Err(FrameError::Malformed(
                            "stream ended in the middle of a frame".into(),
                        ));
                    }
                    return Ok(None);
                }
            }
        }
    }

    /// Frames read so far. After the loop this is the share's chunk count.
    pub fn frames_seen(&self) -> u32 {
        self.frames
    }

    /// Ciphertext bytes counted so far, prefixes included.
    pub fn stored_ct(&self) -> u64 {
        self.stored_ct
    }
}
