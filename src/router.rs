//! Router assembly and the security-header middleware.

use axum::{
    Router,
    extract::Request,
    http::{HeaderName, HeaderValue, header},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
};

use crate::{handlers, import, state::AppState};

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(handlers::index))
        .route("/s/{id}", get(handlers::share_page))
        .route("/s/{id}/meta", get(handlers::share_meta))
        .route("/s/{id}/blob", get(handlers::share_blob))
        .route("/assets/{*path}", get(handlers::asset))
        .route("/healthz", get(handlers::healthz))
        .route("/readyz", get(handlers::readyz))
        .route(
            "/api/v1/shares",
            get(handlers::list_shares).post(handlers::create_share),
        )
        .route("/api/v1/shares/url", post(import::import_share))
        .route("/api/v1/shares/{id}", delete(handlers::revoke_share))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Headers on every response. The CSP has no 'unsafe-inline' and the UI is
/// written to live under it: scripts and styles are separate same-origin
/// files, no inline event handlers, no inline style attributes.
async fn security_headers(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
             img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    // Share pages and API answers are one-recipient data; nothing in the
    // chain may keep a copy, not a proxy, not the browser's back button.
    if path == "/" || path.starts_with("/s/") || path.starts_with("/api/") {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    response
}
