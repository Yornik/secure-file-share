//! Prometheus exposition on a separate listener, exactly like soiree: the
//! main port serves the public, so /metrics never needs to sit behind the
//! `IngressRoute`. Counters are atomics; the one gauge is a live query so it
//! is true even across restarts and replicas.

use std::sync::atomic::Ordering;

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use crate::state::AppState;

pub fn metrics_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(serve_metrics))
        .with_state(state)
}

async fn serve_metrics(State(state): State<AppState>) -> Response {
    let active = match sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM shares WHERE expires_at > now() \
             AND (NOT one_time OR downloads = 0)",
    )
    .fetch_one(&state.pool)
    .await
    {
        Ok(count) => count,
        Err(error) => {
            log::error!("active-shares gauge failed: {error}");
            // -1 is Prometheus' way of saying "scrape known bad".
            -1
        }
    };
    let body = format!(
        concat!(
            "# HELP sfs_build_info Build information for this binary.\n",
            "# TYPE sfs_build_info gauge\n",
            "sfs_build_info{{version=\"{version}\",commit=\"{commit}\"}} 1\n",
            "# HELP sfs_shares_created_total Shares created (uploads and imports).\n",
            "# TYPE sfs_shares_created_total counter\n",
            "sfs_shares_created_total {created}\n",
            "# HELP sfs_downloads_total Share downloads claimed.\n",
            "# TYPE sfs_downloads_total counter\n",
            "sfs_downloads_total {downloads}\n",
            "# HELP sfs_imports_total URL imports by outcome.\n",
            "# TYPE sfs_imports_total counter\n",
            "sfs_imports_total{{result=\"ok\"}} {ok}\n",
            "sfs_imports_total{{result=\"error\"}} {err}\n",
            "# HELP sfs_active_shares Shares live right now (not expired, not burned).\n",
            "# TYPE sfs_active_shares gauge\n",
            "sfs_active_shares {active}\n"
        ),
        version = env!("CARGO_PKG_VERSION"),
        commit = option_env!("SFS_BUILD_COMMIT").unwrap_or("none"),
        created = state.metrics.shares_created.load(Ordering::Relaxed),
        downloads = state.metrics.downloads.load(Ordering::Relaxed),
        ok = state.metrics.imports_ok.load(Ordering::Relaxed),
        err = state.metrics.imports_err.load(Ordering::Relaxed),
        active = active,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )
        .body(axum::body::Body::from(body))
        .unwrap_or_else(|error| {
            // Building this response cannot fail; if it ever does, say so
            // instead of pretending the scrape worked.
            log::error!("metrics response build failed: {error}");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })
}
