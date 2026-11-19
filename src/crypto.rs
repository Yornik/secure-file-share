//! The only cryptography this server performs is for URL imports, where it
//! takes the role of the uploader's browser: a fresh key, per-chunk
//! encryption, and the key handed back in the share link's fragment. Browser
//! uploads arrive already encrypted and this module is never called for
//! them.
//!
//! The wire format (identical in the JavaScript in `static/`):
//!
//! ```text
//! plaintext stream:  [ metadata chunk (JSON, <= 64 KiB) ]
//!                    [ data chunk (<= 4 MiB) ] ...
//! encrypted chunk:   nonce (12 bytes) || AES-256-GCM ciphertext || tag
//! frame on the wire: length of encrypted chunk (u32, big endian)
//!                    || encrypted chunk
//! end of stream:     an empty encrypted chunk (just nonce and tag)
//! ```
//!
//! Per-chunk nonces are random 96-bit values, never derived from a counter:
//! one key protects at most a few thousand chunks here (the upload cap
//! bounds it), far below the 2^32 random-nonce collision birthday bound for
//! AES-GCM. The empty final chunk makes truncation fail its tag check, the
//! same trick age's STREAM construction plays.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, consts::U12},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Upper bound for the metadata chunk's plaintext. Enforced by the frame
/// reader on upload too, so a client cannot park a multi-megabyte "metadata"
/// chunk in seq 0.
pub const META_PLAINTEXT_LIMIT: usize = 64 * 1024;
/// Data chunk size. Small enough that a browser holds at most this much plus
/// one chunk in memory, large enough that the per-frame overhead (16 bytes of
/// nonce and tag per 4 MiB) rounds to nothing.
pub const CHUNK_PLAINTEXT: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("decryption failed")]
pub struct CryptoError;

pub fn new_key() -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    // rand::fill draws from the OS CSPRNG; on failure it panics, which is
    // the right failure mode for a process that cannot generate secrets.
    rand::fill(&mut key);
    key
}

pub fn new_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    rand::fill(&mut nonce);
    nonce
}

/// Share id: 16 random bytes, base64url without padding: 22 characters, no
/// `+` or `/`, safe in a URL path, and 128 bits of entropy so the share list
/// cannot be walked.
pub fn new_id() -> String {
    let mut raw = [0_u8; 16];
    rand::fill(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

pub fn encode_b64_url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_b64_url(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(text)
}

/// Encrypt one chunk. Returns nonce-ciphertext-tag, the frame payload.
pub fn encrypt_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new(&Key::<Aes256Gcm>::try_from(key.as_slice()).map_err(|_| CryptoError)?);
    let nonce = Nonce::<U12>::try_from(nonce.as_slice()).map_err(|_| CryptoError)?;
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| CryptoError)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt one chunk's nonce-ciphertext-tag. Used by the tests to prove the
/// stored bytes round-trip; the production download path serves ciphertext
/// untouched.
pub fn decrypt_chunk(key: &[u8; KEY_LEN], nonce_ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce_ct.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let Some((nonce, ciphertext)) = nonce_ct.split_at_checked(NONCE_LEN) else {
        return Err(CryptoError);
    };
    let cipher =
        Aes256Gcm::new(&Key::<Aes256Gcm>::try_from(key.as_slice()).map_err(|_| CryptoError)?);
    let nonce = Nonce::<U12>::try_from(nonce).map_err(|_| CryptoError)?;
    cipher.decrypt(&nonce, ciphertext).map_err(|_| CryptoError)
}
