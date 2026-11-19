//! HTTP handlers. Two doors only: the admin API (bearer token, everything
//! that creates, lists or deletes shares) and the public share pages (the
//! HTML that does the decrypting, and the ciphertext it fetches). Nothing on
//! the public side ever needs the admin token, and nothing on either side
//! ever sees a plaintext file: the ciphertext is handed through untouched.

use std::io;

use axum::{
    Json,
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::BytesMut;
use futures::{Stream, StreamExt, stream};
use rust_embed::RustEmbed;
use serde::Serialize;
use sqlx::{Row, postgres::PgRow};
use subtle::ConstantTimeEq;

use crate::{
    error::AppError,
    frame::{FrameReader, put_frame},
    state::{AppState, Metrics, ShareWriter, clamp_ttl},
};

/// The web UI ships inside the binary: no CDN, no build step, nothing to
/// subvert from outside.
#[derive(RustEmbed)]
#[folder = "static/"]
struct Assets;

/// The response to a browser-encrypted upload. No `url` on purpose: the
/// server does not know the key, so it cannot build the link — the page
/// that encrypted the file does that from the id and the key it still holds.
#[derive(Serialize)]
pub struct CreateResponse {
    id: String,
    expires_at: String,
}

/// The response to a URL import. Here the server generated the key, so it
/// can (and must) hand back the complete link.
#[derive(Serialize)]
pub struct ImportResponse {
    pub(crate) id: String,
    pub(crate) url: String,
    pub(crate) expires_at: String,
}

#[derive(Serialize)]
pub struct ShareInfo {
    id: String,
    stored_size: i64,
    one_time: bool,
    downloads: i64,
    created_at: String,
    expires_at: String,
}

#[derive(Serialize)]
pub struct ShareMeta {
    one_time: bool,
    burned: bool,
    downloads: i64,
    /// Ciphertext bytes, approximately the file size plus a few bytes per
    /// 4 MiB chunk. Close enough for the page to warn about big downloads.
    stored_size: i64,
    expires_at: String,
}

/// Constant-time bearer check. A timing leak on the comparison would turn
/// the admin token into something an attacker could bisect character by
/// character on a public endpoint.
pub(crate) fn require_admin(headers: &HeaderMap, state: &AppState) -> Result<(), AppError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    let expected = state.config.admin_token.as_bytes();
    let provided = value.as_bytes();
    // The length check first is fine: it leaks only the token's length,
    // which the response time of any request already hints at.
    if provided.len() == expected.len() && bool::from(provided.ct_eq(expected)) {
        Ok(())
    } else {
        Err(AppError::Unauthorized)
    }
}

fn parse_flag(headers: &HeaderMap, name: &str) -> bool {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn parse_ttl(headers: &HeaderMap, state: &AppState) -> i32 {
    let requested = headers
        .get("x-sfs-ttl-days")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<i64>().ok());
    clamp_ttl(&state.config, requested)
}

pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok\n")
}

pub async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (StatusCode::OK, "ok\n"),
        Err(error) => {
            log::error!("readiness check failed: {error}");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
        }
    }
}

pub async fn index() -> Result<Response, AppError> {
    serve_asset("index.html")
}

pub async fn share_page() -> Result<Response, AppError> {
    serve_asset("share.html")
}

pub async fn asset(Path(path): Path<String>) -> Result<Response, AppError> {
    serve_asset(&path)
}

fn serve_asset(name: &str) -> Result<Response, AppError> {
    let asset = Assets::get(name).ok_or(AppError::NotFound)?;
    let mime = mime_guess::from_path(name)
        .first_raw()
        .unwrap_or("application/octet-stream");
    let response = Response::builder()
        .header(header::CONTENT_TYPE, mime)
        .body(Body::from(asset.data.into_owned()))
        .map_err(|error| {
            log::error!("asset response build failed: {error}");
            AppError::Internal("response".into())
        })?;
    Ok(response)
}

/// Admin listing. What an operator sees is exactly what the server knows:
/// sizes, timestamps, counters. No file names — they are inside the
/// encrypted metadata chunk and unreadable here.
pub async fn list_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<ShareInfo>>, AppError> {
    require_admin(&headers, &state)?;
    let rows = sqlx::query(
        "SELECT id, stored_size, one_time, downloads, \
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created, \
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires \
         FROM shares ORDER BY created_at DESC LIMIT 500",
    )
    .fetch_all(&state.pool)
    .await?;
    let shares = rows
        .into_iter()
        .map(|row| ShareInfo {
            id: row.get::<String, _>("id"),
            stored_size: row.get::<i64, _>("stored_size"),
            one_time: row.get::<bool, _>("one_time"),
            downloads: i64::from(row.get::<i32, _>("downloads")),
            created_at: row.get::<String, _>("created"),
            expires_at: row.get::<String, _>("expires"),
        })
        .collect();
    Ok(Json(shares))
}

/// Browser-encrypted upload. The body is the frame stream the JavaScript in
/// `static/app.js` built; this handler never touches a key, it only splits
/// the stream into rows and counts bytes.
pub async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request,
) -> Result<Json<CreateResponse>, AppError> {
    require_admin(&headers, &state)?;
    let one_time = parse_flag(&headers, "x-sfs-one-time");
    let ttl_days = parse_ttl(&headers, &state);
    let stream = request.into_body().into_data_stream();
    let mut reader = FrameReader::new(stream, state.config.max_upload_bytes);
    let (mut writer, _id, expires_at) = ShareWriter::begin(&state.pool, one_time, ttl_days).await?;
    while let Some(frame) = reader.next_frame().await? {
        writer.add_frame(frame).await?;
    }
    let stored = writer.finish().await?;
    Metrics::incr(&state.metrics.shares_created);
    log::info!(
        "stored share {id}: {frames} frames, {stored} bytes (browser-encrypted)",
        id = stored.id,
        frames = stored.frames,
        stored = stored.stored
    );
    Ok(Json(CreateResponse {
        id: stored.id,
        expires_at,
    }))
}

pub async fn revoke_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    require_admin(&headers, &state)?;
    let result = sqlx::query("DELETE FROM shares WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    if result.rows_affected() == 0 {
        Err(AppError::NotFound)
    } else {
        // The chunks go with the row: ON DELETE CASCADE.
        Ok(StatusCode::NO_CONTENT)
    }
}

/// Public share metadata, just enough for the page to decide what to show
/// (a burn warning, an expiry, an "already gone" notice) before the user
/// commits to downloading.
pub async fn share_meta(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ShareMeta>, AppError> {
    let row = sqlx::query(
        "SELECT one_time, downloads, stored_size, \
                expires_at > now() AND (NOT one_time OR downloads = 0) AS live, \
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires \
         FROM shares WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(row) = row else {
        return Err(AppError::NotFound);
    };
    if !row.get::<bool, _>("live") {
        return Err(AppError::Gone);
    }
    let one_time = row.get::<bool, _>("one_time");
    let downloads = i64::from(row.get::<i32, _>("downloads"));
    Ok(Json(ShareMeta {
        one_time,
        burned: one_time && downloads > 0,
        downloads,
        stored_size: row.get::<i64, _>("stored_size"),
        expires_at: row.get::<String, _>("expires"),
    }))
}

/// State carried through the download stream. Frames only: the burn does
/// not happen here. A one-time share is claimed by the UPDATE below and
/// its row stays as a tombstone, so the next opener reads 410 ("burned")
/// instead of 404 ("never existed"); the sweeper reclaims the chunks
/// within the hour.
struct BlobState {
    rows: std::pin::Pin<Box<dyn Stream<Item = Result<PgRow, sqlx::Error>> + Send>>,
}

/// Public ciphertext download. The claim is one statement: `downloads` is
/// bumped in the same UPDATE that decides eligibility, so two racing
/// downloads of a burn-after-reading share cannot both win.
#[allow(clippy::too_many_lines)]
pub async fn share_blob(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, AppError> {
    let claimed = sqlx::query(
        "UPDATE shares SET downloads = downloads + 1, last_downloaded_at = now() \
         WHERE id = $1 AND expires_at > now() AND (NOT one_time OR downloads = 0) \
         RETURNING stored_size",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(claimed) = claimed else {
        // Distinguish "never existed" from "was here and is gone": the
        // second is worth telling the downloader, the first is a scan.
        let existing = sqlx::query_scalar::<_, i32>(
            "SELECT CASE WHEN expires_at <= now() OR (one_time AND downloads > 0) \
             THEN 0 ELSE 1 END FROM shares WHERE id = $1",
        )
        .bind(&id)
        .fetch_optional(&state.pool)
        .await?;
        return match existing {
            Some(0) => Err(AppError::Gone),
            _ => Err(AppError::NotFound),
        };
    };
    Metrics::incr(&state.metrics.downloads);
    let stored_size = claimed.get::<i64, _>("stored_size");

    let rows = sqlx::query("SELECT data FROM share_chunks WHERE share_id = $1 ORDER BY seq")
        .bind(&id)
        .fetch(&state.pool);
    let body = Body::from_stream(stream::unfold(
        BlobState {
            rows: Box::pin(rows),
        },
        |mut st| async move {
            match st.rows.next().await {
                Some(Ok(row)) => match row.try_get::<Vec<u8>, _>("data") {
                    Ok(data) => {
                        let mut frame = BytesMut::with_capacity(4 + data.len());
                        put_frame(&mut frame, &data);
                        Some((Ok(frame.freeze()), st))
                    }
                    Err(error) => {
                        log::error!("chunk read failed: {error}");
                        Some((Err(io::Error::other(error)), st))
                    }
                },
                Some(Err(error)) => {
                    log::error!("chunk stream failed: {error}");
                    Some((Err(io::Error::other(error)), st))
                }
                None => None,
            }
        },
    ));
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, stored_size.to_string())
        .body(body)
        .map_err(|error| {
            log::error!("blob response build failed: {error}");
            AppError::Internal("response".into())
        })
}
