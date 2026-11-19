//! Shared state and the counters the metrics endpoint exposes. Counters are
//! plain atomics: the only thing a restart loses is a number, and the
//! database remains the single source of truth for everything that matters.
//!
//! Storage is two places, each doing what it is good at: ciphertext blobs
//! are plain files on a volume, bookkeeping is rows in Postgres. The
//! database never holds a byte of payload — a claim, a revoke or an expiry
//! can be decided atomically in SQL, while a 2 GiB blob streams off the
//! volume without ever being the database's problem.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bytes::Bytes;
use sqlx::PgPool;
use tokio::io::AsyncWriteExt;

use crate::config::Config;

#[derive(Debug, Default)]
pub struct Metrics {
    pub shares_created: AtomicU64,
    pub downloads: AtomicU64,
    pub imports_ok: AtomicU64,
    pub imports_err: AtomicU64,
    /// Shares the sweeper has deleted (expired or burned). Only the number
    /// lives here; the reclamation it counts is already done, in the
    /// database and on the volume.
    pub sweeper_removed: AtomicU64,
}

impl Metrics {
    pub fn incr(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub pool: PgPool,
    pub metrics: Arc<Metrics>,
    /// Shared HTTP client for URL imports: pooled connections, a redirect
    /// cap, rustls (no openssl, the binary stays pure Rust and builds to
    /// scratch).
    pub http: reqwest::Client,
}

/// Final resting place of one share's ciphertext: `<data_dir>/<id>.sfs`.
/// The id is the file name, so a bookkeeping row can always find its blob,
/// and a blob without a row is an orphan the sweeper removes.
pub fn blob_path(data_dir: &str, id: &str) -> PathBuf {
    Path::new(data_dir).join(format!("{id}.sfs"))
}

/// A share being written, frame by frame, to a file that does not exist yet.
/// Both upload paths build one: the browser-encrypted upload feeds it frames
/// from the request body, the URL import feeds frames it encrypts itself.
///
/// The frames land in `<data_dir>/<id>.tmp-<random>` and are renamed to
/// `<id>.sfs` only after the stream validates, so a partial upload is never
/// a share: a crash or a malformed stream leaves only a temporary file the
/// sweeper removes, and the bookkeeping row rolls back with it.
pub struct ShareWriter<'a> {
    /// `Some` until `finish()` takes it: the `Drop` guard below makes
    /// moving fields out of this struct illegal without it.
    tx: Option<sqlx::Transaction<'a, sqlx::Postgres>>,
    /// `Some` until `finish()` syncs and closes it; the `Drop` guard makes
    /// moving the file out otherwise illegal.
    file: Option<tokio::fs::File>,
    tmp_path: PathBuf,
    id: String,
    stored: i64,
    frames: u32,
    first_len: usize,
    last_len: usize,
}

impl ShareWriter<'_> {
    /// Open the transaction, insert the bookkeeping row, and open the
    /// temporary blob file. `stored_size` is still a placeholder;
    /// `finish()` writes the real value, and without it the transaction
    /// rolls back and neither the row nor the blob ever existed.
    #[allow(clippy::too_many_arguments)]
    pub async fn begin(
        pool: &PgPool,
        data_dir: &str,
        one_time: bool,
        ttl_days: i32,
    ) -> Result<(Self, String, String), crate::error::AppError> {
        let id = crate::crypto::new_id();
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO shares (id, stored_size, one_time, expires_at) \
             VALUES ($1, 0, $2, now() + make_interval(days => $3))",
        )
        .bind(&id)
        .bind(one_time)
        .bind(ttl_days)
        .execute(&mut *tx)
        .await?;
        let expires_at = sqlx::query_scalar::<_, String>(
            "SELECT to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') \
             FROM shares WHERE id = $1",
        )
        .bind(&id)
        .fetch_one(&mut *tx)
        .await?;
        let tmp_path = Path::new(data_dir).join(format!("{id}.tmp-{}", crate::crypto::new_id()));
        let file = tokio::fs::File::create(&tmp_path).await.map_err(|error| {
            log::error!("cannot create the blob file in {data_dir}: {error}");
            crate::error::AppError::Internal("blob file".into())
        })?;
        let writer = Self {
            tx: Some(tx),
            file: Some(file),
            tmp_path,
            id,
            stored: 0,
            frames: 0,
            first_len: 0,
            last_len: 0,
        };
        let id = writer.id.clone();
        Ok((writer, id, expires_at))
    }

    /// Write one frame (length prefix included, exactly as the downloader
    /// will read it back) and count it. `Bytes` so the write reuses the
    /// reader's buffer instead of copying a 4 MiB frame a second time.
    pub async fn add_frame(&mut self, frame: Bytes) -> Result<(), crate::error::AppError> {
        let prefix = u32::try_from(frame.len()).unwrap_or(u32::MAX).to_be_bytes();
        let Some(file) = self.file.as_mut() else {
            return Err(crate::error::AppError::Internal(
                "writer already finished".into(),
            ));
        };
        file.write_all(&prefix)
            .await
            .map_err(|error| crate::error::AppError::io(&error))?;
        file.write_all(&frame)
            .await
            .map_err(|error| crate::error::AppError::io(&error))?;
        self.stored += i64::from(4) + i64::try_from(frame.len()).unwrap_or(i64::MAX);
        if self.frames == 0 {
            self.first_len = frame.len();
        }
        self.frames += 1;
        self.last_len = frame.len();
        Ok(())
    }

    /// Validate the stream's shape and publish. Frame 0 must be the
    /// ML-KEM-1024 ciphertext, the last frame the empty end-of-stream
    /// marker; without the marker a truncated stream would look like a
    /// complete share. The blob is fsynced, renamed into place, the
    /// directory entry fsynced too, and only then does the row commit.
    pub async fn finish(mut self) -> Result<StoredShare, crate::error::AppError> {
        if self.frames < 3 {
            return Err(crate::error::AppError::BadRequest(
                "a share needs an encapsulation frame, a metadata frame and the end-of-stream marker".into(),
            ));
        }
        if self.first_len != crate::crypto::KEM_CT_LEN {
            return Err(crate::error::AppError::BadRequest(
                "frame 0 must be the ML-KEM-1024 ciphertext (1568 bytes)".into(),
            ));
        }
        if self.last_len != crate::frame::empty_frame_ct() {
            return Err(crate::error::AppError::BadRequest(
                "the stream does not end with the end-of-stream marker".into(),
            ));
        }
        if let Some(file) = self.file.as_mut() {
            file.sync_all()
                .await
                .map_err(|error| crate::error::AppError::io(&error))?;
        }
        // Close the handle before the rename: an open File keeps the fsync
        // from being the last word on some platforms.
        drop(self.file.take());
        let final_path = blob_path(
            self.tmp_path
                .parent()
                .and_then(Path::to_str)
                .ok_or_else(|| crate::error::AppError::Internal("blob path".into()))?,
            &self.id,
        );
        tokio::fs::rename(&self.tmp_path, &final_path)
            .await
            .map_err(|error| crate::error::AppError::io(&error))?;
        // The rename is durable only once the directory entry is synced.
        if let Some(parent) = final_path.parent()
            && let Ok(dir) = tokio::fs::File::open(parent).await
        {
            let _ = dir.sync_all().await;
        }
        let Some(tx) = self.tx.as_mut() else {
            return Err(crate::error::AppError::Internal(
                "writer already finished".into(),
            ));
        };
        sqlx::query("UPDATE shares SET stored_size = $2 WHERE id = $1")
            .bind(&self.id)
            .bind(self.stored)
            .execute(&mut **tx)
            .await?;
        let tx = self
            .tx
            .take()
            .ok_or_else(|| crate::error::AppError::Internal("writer already finished".into()))?;
        tx.commit().await?;
        Ok(StoredShare {
            id: self.id.clone(),
            stored: self.stored,
            frames: self.frames,
        })
    }
}

impl Drop for ShareWriter<'_> {
    /// A writer dropped without `finish()` rolls back and takes its
    /// temporary blob with it: the file is open, the transaction
    /// uncommitted. Best-effort on purpose; the sweeper removes stray
    /// `.tmp-` files older than an hour whatever happens here. The removal
    /// is blocking, but it only runs on a failed-upload path that is about
    /// to end anyway.
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.tmp_path) {
            log::debug!("sweeper will remove {}: {error}", self.tmp_path.display());
        }
    }
}

#[derive(Debug)]
pub struct StoredShare {
    pub id: String,
    pub stored: i64,
    pub frames: u32,
}

/// TTL clamp shared by both upload paths: an explicit day count is honoured
/// up to the configured maximum, anything else gets the default.
pub fn clamp_ttl(config: &Config, requested: Option<i64>) -> i32 {
    let max = i64::try_from(config.max_ttl_days).unwrap_or(i64::MAX);
    let days = requested
        .filter(|days| (1..=max).contains(days))
        .unwrap_or(i64::try_from(config.default_ttl_days).unwrap_or(i64::MAX));
    i32::try_from(days).unwrap_or(i32::MAX)
}
