//! Integration tests against the real router and a real Postgres.
//!
//! Set `SFS_TEST_DATABASE_URL` (the CI job does) and these run; without it
//! they skip with a warning, so `cargo test` on a fresh clone stays green.
//! Everything flows through the public surface: the token check, the frame
//! reader, the database transaction, the claim and the download stream.
//!
//! Run with `--test-threads=1`: every test's setup wipes the shared
//! database, so parallel threads race each other's rows. CI does this; do
//! the same locally (`cargo test -- --test-threads=1`).

use std::error::Error;

use axum::{
    Router,
    body::Body,
    http::{HeaderName, Method, Request, StatusCode, header, request::Builder},
};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use secure_file_share::{
    config::Config,
    crypto,
    frame::put_frame,
    router,
    state::{AppState, Metrics},
};

const ADMIN_TOKEN: &str = "test-admin-token-0123456789abcdef";
const BASE_URL: &str = "http://test.local";

/// A complete state wired to the test database, with defaults tuned down so
/// the size limits are testable.
async fn setup() -> Result<Option<(AppState, Router)>, Box<dyn Error>> {
    let Ok(database_url) = std::env::var("SFS_TEST_DATABASE_URL") else {
        log::warn!("SFS_TEST_DATABASE_URL is not set; skipping integration tests");
        return Ok(None);
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    // Each run starts from an empty slate; failures leave rows behind only
    // for as long as the developer's throwaway database lives.
    sqlx::query("DELETE FROM shares").execute(&pool).await?;

    let config = Config {
        listen_addr: "127.0.0.1:18080".parse()?,
        metrics_addr: "127.0.0.1:19090".parse()?,
        database_url,
        admin_token: ADMIN_TOKEN.to_owned(),
        base_url: BASE_URL.to_owned(),
        max_upload_bytes: 1_000_000,
        import_max_bytes: 1_000_000,
        default_ttl_days: 7,
        max_ttl_days: 90,
        sweep_interval: std::time::Duration::from_secs(3600),
    };
    let state = AppState {
        config,
        pool,
        metrics: std::sync::Arc::new(Metrics::default()),
        http: reqwest::Client::new(),
    };
    let app = router::app(state.clone());
    Ok(Some((state, app)))
}

async fn call(
    app: &mut Router,
    builder: Builder,
    body: Vec<u8>,
) -> Result<(StatusCode, Vec<u8>), Box<dyn Error>> {
    let body = if body.is_empty() {
        Body::empty()
    } else {
        Body::from(body)
    };
    let request = builder.body(body)?;
    let response = app.oneshot(request).await?;
    let status = response.status();
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok((status, bytes.to_vec()))
}

fn post(path: &str) -> Builder {
    Request::builder().method(Method::POST).uri(path)
}

fn get(path: &str) -> Builder {
    Request::builder().method(Method::GET).uri(path)
}

fn delete(path: &str) -> Builder {
    Request::builder().method(Method::DELETE).uri(path)
}

fn authorized(mut builder: Builder) -> Builder {
    builder = builder.header(header::AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"));
    builder
}

/// A metadata chunk's plaintext, in the exact shape `static/app.js` writes.
fn meta_json(name: &str, mime: &str, size: u64) -> Vec<u8> {
    serde_json::json!({ "name": name, "mime": mime, "size": size })
        .to_string()
        .into_bytes()
}

/// Build a complete encrypted stream: metadata, data, end marker.
fn encrypted_stream(
    key: &[u8; crypto::KEY_LEN],
    meta: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut out = bytes::BytesMut::new();
    let meta_frame = crypto::encrypt_chunk(key, &crypto::new_nonce(), meta)
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    put_frame(&mut out, &meta_frame);
    let data_frame = crypto::encrypt_chunk(key, &crypto::new_nonce(), data)
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    put_frame(&mut out, &data_frame);
    let marker = crypto::encrypt_chunk(key, &crypto::new_nonce(), &[])
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    put_frame(&mut out, &marker);
    Ok(out.to_vec())
}

/// Parse a downloaded stream back into frames and decrypt them.
fn decrypt_stream(
    key: &[u8; crypto::KEY_LEN],
    stream: &[u8],
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut frames = Vec::new();
    let mut offset = 0_usize;
    while offset + 4 <= stream.len() {
        let prefix = stream
            .get(offset..offset + 4)
            .ok_or("truncated length prefix")?;
        let len = u32::from_be_bytes(prefix.try_into()?) as usize;
        let end = offset + 4 + len;
        let frame = stream.get(offset + 4..end).ok_or("truncated frame")?;
        frames.push(
            crypto::decrypt_chunk(key, frame)
                .map_err(|_| "decrypt failed: wrong key or corrupted share".to_owned())?,
        );
        offset = end;
    }
    if offset != stream.len() {
        return Err("trailing bytes".into());
    }
    Ok(frames)
}

async fn status_of(app: &mut Router, path: &str) -> Result<StatusCode, Box<dyn Error>> {
    let (status, _) = call(app, get(path), Vec::new()).await?;
    Ok(status)
}

/// Everything a browser upload, a URL import, an expiry, a burn and a
/// revoke do, in the order a user would do them. Splitting it into separate
/// tests would hide that sequence; the point is the sequence.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn end_to_end() -> Result<(), Box<dyn Error>> {
    let Some((state, mut app)) = setup().await? else {
        return Ok(());
    };

    // Health endpoints.
    let (status, _) = call(&mut app, get("/healthz"), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = call(&mut app, get("/readyz"), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);

    // No token, no service.
    let (status, _) = call(&mut app, post("/api/v1/shares"), vec![1, 2, 3]).await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Garbage is not a share.
    let (status, _) = call(
        &mut app,
        authorized(post("/api/v1/shares")),
        vec![0xFF; 100],
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A stream without the end-of-stream marker is refused whole.
    let key = crypto::new_key();
    let markerless = {
        let mut out = bytes::BytesMut::new();
        let meta = crypto::encrypt_chunk(
            &key,
            &crypto::new_nonce(),
            &meta_json("a.bin", "text/plain", 1),
        )
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
        put_frame(&mut out, &meta);
        out.to_vec()
    };
    let (status, _) = call(&mut app, authorized(post("/api/v1/shares")), markerless).await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // A burn-after-reading share: create, list, fetch meta, download once,
    // then the link is dead.
    let plaintext = b"hello from the integration test".to_vec();
    let stream = encrypted_stream(
        &key,
        &meta_json("hello.txt", "text/plain", plaintext.len() as u64),
        &plaintext,
    )?;
    let (status, body) = call(
        &mut app,
        authorized(
            post("/api/v1/shares")
                .header("x-sfs-one-time", "1")
                .header("x-sfs-ttl-days", "3"),
        ),
        stream,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "create: {}",
        String::from_utf8_lossy(&body)
    );
    let created: Value = serde_json::from_slice(&body)?;
    let id = created
        .get("id")
        .and_then(Value::as_str)
        .ok_or("no id in response")?
        .to_owned();
    assert!(created.get("expires_at").is_some(), "expiry is announced");

    // The admin list sees the share, and nothing about its name.
    let (status, body) = call(&mut app, authorized(get("/api/v1/shares")), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let listed: Value = serde_json::from_slice(&body)?;
    assert_eq!(listed.as_array().map(Vec::len), Some(1), "one share listed");
    assert!(
        !listed.to_string().contains("hello.txt"),
        "no file name in the admin listing"
    );

    // Meta before the download.
    let (status, body) = call(&mut app, get(&format!("/s/{id}/meta")), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let meta: Value = serde_json::from_slice(&body)?;
    assert_eq!(meta.get("one_time").and_then(Value::as_bool), Some(true));
    assert_eq!(meta.get("burned").and_then(Value::as_bool), Some(false));

    // The download decrypts to exactly the plaintext.
    let (status, body) = call(&mut app, get(&format!("/s/{id}/blob")), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let frames = decrypt_stream(&key, &body)?;
    assert_eq!(frames.len(), 3, "meta, data, marker");
    let meta_back: Value = serde_json::from_slice(frames.first().ok_or("no meta frame")?)?;
    assert_eq!(
        meta_back.get("name").and_then(Value::as_str),
        Some("hello.txt")
    );
    assert_eq!(
        frames.get(1).map(Vec::as_slice),
        Some(plaintext.as_slice()),
        "round-trip is byte-identical"
    );
    assert_eq!(frames.last().map(Vec::len), Some(0), "empty end marker");

    // Burned: the second download is refused and the meta agrees.
    assert_eq!(
        status_of(&mut app, &format!("/s/{id}/blob")).await?,
        StatusCode::GONE
    );
    let (status, _) = call(&mut app, get(&format!("/s/{id}/meta")), Vec::new()).await?;
    assert_eq!(status, StatusCode::GONE);

    // A multi-download share stays alive until revoked.
    let key2 = crypto::new_key();
    let stream2 = encrypted_stream(&key2, &meta_json("keep.txt", "text/plain", 5), b"again")?;
    let (status, body) = call(
        &mut app,
        authorized(post("/api/v1/shares").header("x-sfs-ttl-days", "9999")),
        stream2,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "an absurd TTL is clamped, not fatal"
    );
    let id2: Value = serde_json::from_slice(&body)?;
    let id2 = id2
        .get("id")
        .and_then(Value::as_str)
        .ok_or("no id")?
        .to_owned();
    assert_eq!(
        status_of(&mut app, &format!("/s/{id2}/blob")).await?,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&mut app, &format!("/s/{id2}/blob")).await?,
        StatusCode::OK
    );
    let (status, _) = call(
        &mut app,
        authorized(delete(&format!("/api/v1/shares/{id2}"))),
        Vec::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        status_of(&mut app, &format!("/s/{id2}/meta")).await?,
        StatusCode::NOT_FOUND
    );

    // Unknown ids are a 404, not a 410: nobody should learn that a link
    // they never had used to exist.
    assert_eq!(
        status_of(&mut app, "/s/does-not-exist/meta").await?,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status_of(&mut app, "/s/does-not-exist/blob").await?,
        StatusCode::NOT_FOUND
    );

    // An expired share answers 410 until the sweeper removes it.
    sqlx::query(
        "INSERT INTO shares (id, stored_size, chunk_count, one_time, expires_at) \
         VALUES ('expired-test-id', 0, 0, false, now() - interval '1 hour')",
    )
    .execute(&state.pool)
    .await?;
    assert_eq!(
        status_of(&mut app, "/s/expired-test-id/meta").await?,
        StatusCode::GONE
    );

    Ok(())
}

/// URL import: a tiny upstream server, a fetch, a decrypt — proving the
/// server-side path produces the same stream format the browser does.
#[tokio::test]
async fn url_import() -> Result<(), Box<dyn Error>> {
    let Some((_, mut app)) = setup().await? else {
        return Ok(());
    };

    let payload = b"imported through the server".to_vec();
    let upstream = axum::Router::new().route(
        "/file.bin",
        axum::routing::get(move || {
            let payload = payload.clone();
            async move {
                (
                    [
                        (header::CONTENT_TYPE, "application/octet-stream"),
                        (
                            HeaderName::from_static("content-disposition"),
                            "attachment; filename=\"upstream file.bin\"",
                        ),
                    ],
                    payload,
                )
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, upstream).await {
            log::error!("upstream test server failed: {error}");
        }
    });

    let request = serde_json::json!({
        "url": format!("http://{addr}/file.bin"),
        "ttl_days": 7,
        "one_time": false,
    });
    let (status, body) = call(
        &mut app,
        authorized(post("/api/v1/shares/url")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&request)?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "import: {}",
        String::from_utf8_lossy(&body)
    );
    let imported: Value = serde_json::from_slice(&body)?;
    let link = imported
        .get("url")
        .and_then(Value::as_str)
        .ok_or("no url in import response")?
        .to_owned();
    let (_, key_part) = link
        .split_once("#key=")
        .ok_or("import link has no key fragment")?;
    let key_bytes = crypto::decode_b64_url(key_part)?;
    let key: [u8; crypto::KEY_LEN] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "key is not 32 bytes")?;
    let id = imported
        .get("id")
        .and_then(Value::as_str)
        .ok_or("no id")?
        .to_owned();

    let (status, body) = call(&mut app, get(&format!("/s/{id}/blob")), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let frames = decrypt_stream(&key, &body)?;
    assert_eq!(frames.len(), 3, "meta, data, marker");
    let meta: Value = serde_json::from_slice(frames.first().ok_or("no meta")?)?;
    assert_eq!(
        meta.get("name").and_then(Value::as_str),
        Some("upstream file.bin"),
        "the Content-Disposition name wins over the URL segment"
    );
    assert_eq!(
        frames.get(1).map(Vec::as_slice),
        Some(b"imported through the server".as_slice())
    );

    // The import path leaks nothing into the state the server keeps: the
    // share row knows sizes, not names.
    let (status, body) = call(&mut app, authorized(get("/api/v1/shares")), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !String::from_utf8_lossy(&body).contains("upstream file.bin"),
        "no name in the listing"
    );

    // A non-2xx upstream is an error, not a share of an error page.
    let bad = serde_json::json!({ "url": format!("http://{addr}/nope") });
    let (status, _) = call(
        &mut app,
        authorized(post("/api/v1/shares/url")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&bad)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    Ok(())
}

/// The admin token is compared in constant time and rejects quietly.
#[tokio::test]
async fn wrong_tokens_get_no_details() -> Result<(), Box<dyn Error>> {
    let Some((_, mut app)) = setup().await? else {
        return Ok(());
    };
    for token in ["", "nope", "test-admin-token-0123456789abcdeX"] {
        let builder = Request::builder()
            .method(Method::GET)
            .uri("/api/v1/shares")
            .header(header::AUTHORIZATION, format!("Bearer {token}"));
        let (status, body) = call(&mut app, builder, Vec::new()).await?;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            String::from_utf8_lossy(&body).contains("unauthorized"),
            "the error names no reason"
        );
    }
    // A token that is not even a Bearer scheme.
    let (status, _) = call(
        &mut app,
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/shares")
            .header(header::AUTHORIZATION, ADMIN_TOKEN),
        Vec::new(),
    )
    .await?;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    Ok(())
}

/// The oversize guard: a share past the configured cap is refused before
/// any of its bytes reach the database.
#[tokio::test]
async fn oversize_is_refused() -> Result<(), Box<dyn Error>> {
    let Some((_, mut app)) = setup().await? else {
        return Ok(());
    };
    // The cap in this test's config is 1 MB; one data frame of a million
    // bytes plus the metadata frame crosses it while the frame itself is
    // still legal (the per-frame limit is 4 MiB).
    let key = crypto::new_key();
    let stream = encrypted_stream(
        &key,
        &meta_json("big.bin", "application/octet-stream", 1_000_000),
        &vec![0_u8; 1_000_000],
    )?;
    let (status, _) = call(&mut app, authorized(post("/api/v1/shares")), stream).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    Ok(())
}
