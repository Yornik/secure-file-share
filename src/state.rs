//! Shared state and the counters the metrics endpoint exposes. Counters are
//! plain atomics: the only thing a restart loses is a number, and the
//! database remains the single source of truth for everything that matters.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use sqlx::PgPool;

use crate::config::Config;

#[derive(Debug, Default)]
pub struct Metrics {
    pub shares_created: AtomicU64,
    pub downloads: AtomicU64,
    pub imports_ok: AtomicU64,
    pub imports_err: AtomicU64,
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

/// A share being written into the database, frame by frame. Both upload
/// paths build one: the browser-encrypted upload feeds it frames from the
/// request body, the URL import feeds frames it encrypts itself. Everything
/// lives inside one transaction, so a stream that turns out malformed
/// mid-way rolls back and leaves no orphan rows behind.
pub struct ShareWriter<'a> {
    tx: sqlx::Transaction<'a, sqlx::Postgres>,
    id: String,
    seq: i32,
    stored: i64,
    frames: u32,
    last_len: usize,
}

impl ShareWriter<'_> {
    /// Open the transaction and insert the share row. `chunk_count` and
    /// `stored_size` are still placeholders here; `finish()` writes the real
    /// values, and without it the transaction rolls back and the row never
    /// existed.
    pub async fn begin(
        pool: &PgPool,
        one_time: bool,
        ttl_days: i32,
    ) -> Result<(Self, String, String), sqlx::Error> {
        let id = crate::crypto::new_id();
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO shares (id, stored_size, chunk_count, one_time, expires_at)
             VALUES ($1, 0, 0, $2, now() + make_interval(days => $3))",
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
        let writer = Self {
            tx,
            id,
            seq: 0,
            stored: 0,
            frames: 0,
            last_len: 0,
        };
        let id = writer.id.clone();
        Ok((writer, id, expires_at))
    }

    pub async fn add_frame(&mut self, frame: Vec<u8>) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO share_chunks (share_id, seq, data) VALUES ($1, $2, $3)")
            .bind(&self.id)
            .bind(self.seq)
            .bind(&frame)
            .execute(&mut *self.tx)
            .await?;
        self.stored += i64::try_from(4 + frame.len()).unwrap_or(i64::MAX);
        self.frames += 1;
        self.seq += 1;
        self.last_len = frame.len();
        Ok(())
    }

    /// Validate the stream's shape and commit. The last frame must be the
    /// empty end-of-stream marker; without it a truncated stream would look
    /// like a complete share.
    pub async fn finish(mut self) -> Result<StoredShare, crate::error::AppError> {
        if self.frames < 2 {
            return Err(crate::error::AppError::BadRequest(
                "a share needs a metadata frame and the end-of-stream marker".into(),
            ));
        }
        if self.last_len != crate::frame::empty_frame_ct() {
            return Err(crate::error::AppError::BadRequest(
                "the stream does not end with the end-of-stream marker".into(),
            ));
        }
        sqlx::query("UPDATE shares SET stored_size = $2, chunk_count = $3 WHERE id = $1")
            .bind(&self.id)
            .bind(self.stored)
            .bind(i32::try_from(self.frames).unwrap_or(i32::MAX))
            .execute(&mut *self.tx)
            .await?;
        self.tx.commit().await?;
        Ok(StoredShare {
            id: self.id,
            stored: self.stored,
            frames: self.frames,
        })
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
