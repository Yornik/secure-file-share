//! The control plane: the operator door. The public API has no deletion
//! route in any mode, so revocation lives here, on its own listener,
//! behind its own token. The door that deletes is not the door that
//! uploads: a leaked upload token cannot burn the archive, and the
//! not-public mode cannot leave the delete path open with it.
//!
//! The split inside the listener is deliberate: the page and its
//! assets load without the token — a browser navigation cannot attach
//! an Authorization header, so a gated page would 401 the operator
//! before they could type anything — while the two API routes sit
//! behind the constant-time bearer check below. The page is a form,
//! not a secret: its bytes are the same ones the public listener's
//! asset route already serves, and the token rides with the fetch
//! calls the page makes, never with the page load. The listener itself
//! is reached with a port-forward; the token is the second door.

use axum::{
    Json, Router,
    extract::{Request, State},
    http::header,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use subtle::ConstantTimeEq;

use crate::{
    error::AppError,
    handlers,
    state::{AppState, blob_path},
};

/// The bookkeeping row as this listener answers it: sizes, times and
/// counters, the same fields the admin listing serves, so an operator
/// reads one format everywhere. No file name and nothing decryptable —
/// the database keeps none of that.
#[derive(Serialize)]
struct ShareRecord {
    id: String,
    stored_size: i64,
    one_time: bool,
    downloads: i64,
    created_at: String,
    expires_at: String,
}

/// What both operations receive: the share link exactly as a recipient
/// got it, or a bare id. The unlock fragment is cut away during
/// parsing — the id, not the key, is what the bookkeeping rows are
/// filed under, and the key never reaches this process anyway.
#[derive(Deserialize)]
struct LinkRequest {
    link: String,
}

pub fn control_router(state: AppState) -> Router {
    Router::new()
        // The two API routes go first, so the gate below wraps exactly
        // them and nothing else.
        .route("/lookup", post(lookup))
        .route("/delete", post(delete))
        // `route_layer`, not `layer`: it wraps only the routes added
        // before this call, so the page and its assets stay outside.
        // The gate is added before the headers, so the headers sit
        // outside the gate and even a 401 leaves dressed like every
        // public answer.
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_control_token,
        ))
        // The page and its assets come after the gate on purpose. A
        // browser navigation cannot attach an Authorization header, so
        // the operator's documented flow — port-forward, open the page,
        // type the token into it — would die on a 401 before the form
        // ever rendered. The bytes are no secret either: the same files
        // are embedded in the public listener's asset route.
        .route("/", get(control_index))
        .route("/assets/{*path}", get(handlers::asset))
        .layer(middleware::from_fn(crate::router::security_headers))
        .with_state(state)
}

/// The constant-time bearer check for the control token, mirroring
/// `require_upload_token`. The length check first is fine: it leaks
/// only the token's length, which the response time of any request
/// already hints at.
///
/// Unlike the upload door there is no empty-means-open mode. An empty
/// configured token means no control plane exists (`main` never binds
/// the listener), and a router built by mistake must stay closed, not
/// become an open door.
async fn require_control_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    let expected = state.config.control_token.as_bytes();
    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default();
    let authorized = !expected.is_empty()
        && provided.len() == expected.len()
        && bool::from(provided.as_bytes().ct_eq(expected));
    if authorized {
        Ok(next.run(request).await)
    } else {
        Err(AppError::Unauthorized)
    }
}

/// The portal page, from the same embedded folder the public listener
/// serves: the control plane ships no HTML of its own, only two fields
/// wired to the two routes below.
async fn control_index() -> Result<Response, AppError> {
    handlers::serve_asset("control.html")
}

/// Pull the share id out of whatever the operator pasted: a full link
/// (`https://host/s/<id>#key=...`), a bare path (`/s/<id>`) or a bare
/// id. The id is the segment after the last `/s/`, cut at the fragment
/// or the query; a string with no `/s/` in it is a bare id, taken
/// whole and trimmed.
///
/// A `/` inside the result means the paste was not a share link, and a
/// 400 says so — a 404 would send the operator hunting for a share
/// that never existed.
fn share_id_from_link(link: &str) -> Result<String, AppError> {
    let trimmed = link.trim();
    let id = match trimmed.rfind("/s/") {
        // `get` instead of slicing keeps the lint denials honest even
        // on hostile input; the range is always in bounds.
        Some(at) => trimmed
            .get(at + 3..)
            .unwrap_or_default()
            .split(['#', '?'])
            .next()
            .unwrap_or_default(),
        None => trimmed,
    };
    if id.is_empty() {
        return Err(AppError::BadRequest(
            "the link carries no share id".to_owned(),
        ));
    }
    if id.contains('/') {
        return Err(AppError::BadRequest(
            "not a share link: the id would contain a '/'".to_owned(),
        ));
    }
    Ok(id.to_owned())
}

/// Map one query result row to the answer shape. Same columns, same
/// names as the admin listing, so nothing here invents its own format.
fn share_record(row: &sqlx::postgres::PgRow) -> ShareRecord {
    ShareRecord {
        id: row.get::<String, _>("id"),
        stored_size: row.get::<i64, _>("stored_size"),
        one_time: row.get::<bool, _>("one_time"),
        downloads: i64::from(row.get::<i32, _>("downloads")),
        created_at: row.get::<String, _>("created"),
        expires_at: row.get::<String, _>("expires"),
    }
}

/// POST /lookup: the bookkeeping row for one share, by link. The
/// operator sees the row even when the share is expired or burned —
/// this is bookkeeping, not the public metadata, and "what did we hold
/// and until when" is exactly what a compliance request asks.
async fn lookup(
    State(state): State<AppState>,
    Json(request): Json<LinkRequest>,
) -> Result<Json<ShareRecord>, AppError> {
    let id = share_id_from_link(&request.link)?;
    let row = sqlx::query(
        "SELECT id, stored_size, one_time, downloads, \
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created, \
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires \
         FROM shares WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(row) = row else {
        return Err(AppError::NotFound);
    };
    Ok(Json(share_record(&row)))
}

/// POST /delete: revoke one share, by link. The DELETE returns the
/// row it removed, so the answer is exactly the bookkeeping that
/// stopped existing — one statement, no window in which two operators
/// could act on the same share twice.
async fn delete(
    State(state): State<AppState>,
    Json(request): Json<LinkRequest>,
) -> Result<Json<ShareRecord>, AppError> {
    let id = share_id_from_link(&request.link)?;
    let row = sqlx::query(
        "DELETE FROM shares WHERE id = $1 \
         RETURNING id, stored_size, one_time, downloads, \
                to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS created, \
                to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS expires, \
                to_char(last_downloaded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') AS last",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?;
    let Some(row) = row else {
        // No row, no deletion — and no guess at an orphan file either:
        // the control plane acts only on what the bookkeeping vouches
        // for, and a blob without a row is the sweeper's business.
        return Err(AppError::NotFound);
    };
    let record = share_record(&row);
    let last_downloaded = row.get::<Option<String>, _>("last");
    // The audit line goes out the moment the deletion is a fact,
    // before the file removal: a crash between the two still leaves
    // the compliance evidence that the row died, not a silent gap in
    // the log.
    log::info!(
        "audit: control plane deleted share {}: {} bytes stored, created {}, expires {}, last downloaded {}",
        record.id,
        record.stored_size,
        record.created_at,
        record.expires_at,
        last_downloaded.as_deref().unwrap_or("never")
    );
    // Best-effort on purpose: the row is gone, so a file left behind
    // is a straggler, not a share. A failing volume must not turn a
    // done deletion into a reported failure after the fact is already
    // logged; the next sweep or the next operator pass picks the
    // straggler up.
    if let Err(error) = tokio::fs::remove_file(blob_path(&state.config.data_dir, &record.id)).await
    {
        log::warn!(
            "control plane deleted the row for {} but the blob file stayed: {error}",
            record.id
        );
    }
    Ok(Json(record))
}
