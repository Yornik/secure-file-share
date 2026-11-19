//! Integration tests against the real router, a real Postgres and a real
//! blob directory.
//!
//! Set `SFS_TEST_DATABASE_URL` (the CI job does) and these run; without it
//! they skip with a warning, so `cargo test` on a fresh clone stays green.
//! Everything flows through the public surface: the token check, the frame
//! reader, the blob file, the claim and the download stream.
//!
//! Run with `--test-threads=1`: every test's setup wipes the shared
//! database, so parallel threads race each other's rows. Each run gets its
//! own blob directory, but one serialized database beats flaky checks. CI
//! does this; do the same locally (`cargo test -- --test-threads=1`).

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
    control, crypto,
    frame::put_frame,
    import, metrics, router,
    state::{AppState, Metrics, blob_path},
};

const ADMIN_TOKEN: &str = "test-admin-token-0123456789abcdef";
const CONTROL_TOKEN: &str = "test-control-token-0123456789";
const BASE_URL: &str = "http://test.local";

/// A complete state wired to the test database and a throwaway blob
/// directory, with size limits tuned down so they are testable.
/// The default state: the upload token guards the write paths, and
/// private import hosts are allowed (the URL-import test fetches from
/// a loopback upstream).
async fn setup() -> Result<Option<(AppState, Router)>, Box<dyn Error>> {
    setup_with(false, true).await
}

/// `not_public = true` builds the state of a deployment that set
/// `NOT_PUBLIC_FACING_TURN_OFF_UPLOAD_TOKEN`: no token, and the write
/// paths are open to whatever network can reach them.
/// `allow_private` mirrors `SFS_IMPORT_ALLOW_PRIVATE_URLS`: `true` the
/// way a tailnet deployment would set it, `false` the guarded default.
async fn setup_with(
    not_public: bool,
    allow_private: bool,
) -> Result<Option<(AppState, Router)>, Box<dyn Error>> {
    let Some(state) = setup_state(not_public, allow_private, String::new()).await? else {
        return Ok(None);
    };
    let app = router::app(state.clone());
    Ok(Some((state, app)))
}

/// The state on its own, so a test can wire it to whichever routers it
/// needs: the control-plane test binds one state to both the public
/// app and the control app. `control_token` seeds the control plane's
/// bearer; every other test passes an empty one, which starts no
/// control plane.
async fn setup_state(
    not_public: bool,
    allow_private: bool,
    control_token: String,
) -> Result<Option<AppState>, Box<dyn Error>> {
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

    let data_dir = std::env::temp_dir().join(format!("sfs-test-{}", crypto::new_id()));
    tokio::fs::create_dir_all(&data_dir).await?;
    let data_dir = data_dir
        .to_str()
        .ok_or("temp path is not valid UTF-8")?
        .to_owned();

    let config = Config {
        listen_addr: "127.0.0.1:18080".parse()?,
        metrics_addr: "127.0.0.1:19090".parse()?,
        database_url,
        data_dir,
        upload_token: if not_public {
            String::new()
        } else {
            ADMIN_TOKEN.to_owned()
        },
        not_public_facing_turn_off_upload_token: not_public,
        control_token,
        control_addr: "127.0.0.1:18081".parse()?,
        import_allow_private_urls: allow_private,
        base_url: BASE_URL.to_owned(),
        max_upload_bytes: 1_000_000,
        import_max_bytes: 1_000_000,
        default_ttl_days: 7,
        max_ttl_days: 90,
        sweep_interval: std::time::Duration::from_secs(3600),
    };
    let state = AppState {
        config: config.clone(),
        pool,
        metrics: std::sync::Arc::new(Metrics::default()),
        // The real client the binary runs, guard included: the tests
        // exercise the same wiring a deployment gets.
        http: import::http_client(allow_private),
    };
    Ok(Some(state))
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

fn control_authorized(mut builder: Builder) -> Builder {
    builder = builder.header(header::AUTHORIZATION, format!("Bearer {CONTROL_TOKEN}"));
    builder
}

/// A metadata chunk's plaintext, in the exact shape `static/app.js` writes.
fn meta_json(name: &str, mime: &str, size: u64) -> Vec<u8> {
    serde_json::json!({ "name": name, "mime": mime, "size": size })
        .to_string()
        .into_bytes()
}

/// Build a complete encrypted stream, unlock material included:
/// [encapsulation][metadata][data][end marker], framed.
fn encrypted_stream(
    sk_seed: &[u8; crypto::SK_SEED_LEN],
    rnd: &[u8; crypto::RND_LEN],
    meta: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let (kem_ct, file_key) = crypto::kem_encapsulate(sk_seed, rnd);
    let mut out = bytes::BytesMut::new();
    put_frame(&mut out, &kem_ct);
    let meta_frame = crypto::encrypt_chunk(&file_key, &crypto::new_nonce(), meta)
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    put_frame(&mut out, &meta_frame);
    let data_frame = crypto::encrypt_chunk(&file_key, &crypto::new_nonce(), data)
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    put_frame(&mut out, &data_frame);
    let marker = crypto::encrypt_chunk(&file_key, &crypto::new_nonce(), &[])
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    put_frame(&mut out, &marker);
    Ok(out.to_vec())
}

/// Parse a downloaded stream back into plaintext frames, proving the whole
/// post-quantum hybrid round-trips through the server's own primitives.
fn decrypt_stream(
    sk_seed: &[u8; crypto::SK_SEED_LEN],
    rnd: &[u8; crypto::RND_LEN],
    stream: &[u8],
) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut frames = Vec::new();
    let mut offset = 0_usize;
    let mut file_key: Option<[u8; crypto::KEY_LEN]> = None;
    while offset + 4 <= stream.len() {
        let prefix = stream
            .get(offset..offset + 4)
            .ok_or("truncated length prefix")?;
        let len = u32::from_be_bytes(prefix.try_into()?) as usize;
        let end = offset + 4 + len;
        let frame = stream.get(offset + 4..end).ok_or("truncated frame")?;
        if file_key.is_none() {
            // Frame 0: the raw ML-KEM-1024 ciphertext.
            let ct: [u8; crypto::KEM_CT_LEN] = frame
                .try_into()
                .map_err(|_| "kem frame is the wrong size")?;
            file_key = Some(crypto::kem_decapsulate(sk_seed, rnd, &ct));
        } else {
            let key = file_key.as_ref().ok_or("no key")?;
            frames.push(
                crypto::decrypt_chunk(key, frame)
                    .map_err(|_| "decrypt failed: wrong key or corrupted share".to_owned())?,
            );
        }
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
    let (sk_seed, rnd) = crypto::new_share_seeds();
    let (kem_ct, file_key) = crypto::kem_encapsulate(&sk_seed, &rnd);
    let markerless = {
        let mut out = bytes::BytesMut::new();
        put_frame(&mut out, &kem_ct);
        let meta = crypto::encrypt_chunk(
            &file_key,
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
        &sk_seed,
        &rnd,
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

    // The blob is a file on the volume now, and it begins with the
    // encapsulation frame.
    let blob = tokio::fs::read(blob_path(&state.config.data_dir, &id)).await?;
    let kem_len = u32::from_be_bytes(blob.get(..4).ok_or("short blob")?.try_into()?) as usize;
    assert_eq!(kem_len, crypto::KEM_CT_LEN, "frame 0 is the encapsulation");

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

    // The download decrypts to exactly the plaintext, through the full
    // post-quantum hybrid.
    let (status, body) = call(&mut app, get(&format!("/s/{id}/blob")), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let frames = decrypt_stream(&sk_seed, &rnd, &body)?;
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

    // A multi-download share stays alive until it expires: there is no
    // revocation on the public side, and the DELETE route is gone in
    // every mode. A request that would have revoked is now just a 404.
    let (sk2, rnd2) = crypto::new_share_seeds();
    let stream2 = encrypted_stream(
        &sk2,
        &rnd2,
        &meta_json("keep.txt", "text/plain", 5),
        b"again",
    )?;
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
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the DELETE route does not exist on the public side, with or without a token"
    );
    // The refused delete changes nothing: the share and its blob live on.
    assert_eq!(
        status_of(&mut app, &format!("/s/{id2}/meta")).await?,
        StatusCode::OK
    );
    assert!(
        tokio::fs::try_exists(blob_path(&state.config.data_dir, &id2)).await?,
        "a 404 delete left the blob in place"
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
        "INSERT INTO shares (id, stored_size, one_time, expires_at) \
         VALUES ('expired-test-id', 0, false, now() - interval '1 hour')",
    )
    .execute(&state.pool)
    .await?;
    assert_eq!(
        status_of(&mut app, "/s/expired-test-id/meta").await?,
        StatusCode::GONE
    );

    let _ = tokio::fs::remove_dir_all(&state.config.data_dir).await;
    Ok(())
}

/// URL import: a tiny upstream server, a fetch, a decrypt — proving the
/// server-side path produces the same hybrid stream format the browser
/// does, including the unlock material in the returned link.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn url_import() -> Result<(), Box<dyn Error>> {
    let Some((state, mut app)) = setup().await? else {
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
        .ok_or("import link has no unlock fragment")?;
    let unlock = crypto::decode_b64_url(key_part)?;
    let unlock: [u8; crypto::FRAGMENT_LEN] = unlock
        .try_into()
        .map_err(|_| "unlock material is the wrong size")?;
    let (sk_seed, rnd) = unlock.split_at(crypto::SK_SEED_LEN);
    let sk_seed: [u8; crypto::SK_SEED_LEN] = sk_seed.try_into().map_err(|_| "seed slice")?;
    let rnd: [u8; crypto::RND_LEN] = rnd.try_into().map_err(|_| "rnd slice")?;
    let id = imported
        .get("id")
        .and_then(Value::as_str)
        .ok_or("no id")?
        .to_owned();

    let (status, body) = call(&mut app, get(&format!("/s/{id}/blob")), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let frames = decrypt_stream(&sk_seed, &rnd, &body)?;
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
    let _ = tokio::fs::remove_dir_all(&state.config.data_dir).await;
    Ok(())
}

/// The metrics listener: the operator series are in the exposition, and
/// the SQL gauge behind `sfs_stored_bytes` agrees with the volume. The
/// sweeper counter is served and still zero: no pass ran in this test.
#[tokio::test]
async fn metrics_expose_the_new_series() -> Result<(), Box<dyn Error>> {
    let Some((state, mut app)) = setup().await? else {
        return Ok(());
    };

    // One authorized upload, so the gauges have something true to count.
    let (sk_seed, rnd) = crypto::new_share_seeds();
    let plaintext = b"metrics exposition test".to_vec();
    let stream = encrypted_stream(
        &sk_seed,
        &rnd,
        &meta_json("metrics.txt", "text/plain", plaintext.len() as u64),
        &plaintext,
    )?;
    let (status, body) = call(&mut app, authorized(post("/api/v1/shares")), stream).await?;
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
    let blob_len = tokio::fs::read(blob_path(&state.config.data_dir, &id))
        .await?
        .len();

    let mut metrics_app = metrics::metrics_router(state.clone());
    let (status, body) = call(&mut metrics_app, get("/metrics"), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let exposition = String::from_utf8_lossy(&body).into_owned();

    // One series of the exposition: the value on the line that starts with
    // this exact name. HELP lines start with `#`, so they never match.
    let series = |name: &str| {
        exposition
            .lines()
            .find_map(|line| line.strip_prefix(name).map(str::trim))
            .and_then(|value| value.parse::<i64>().ok())
    };

    assert!(
        exposition.contains("sfs_stored_bytes"),
        "the stored-bytes gauge is served"
    );
    assert!(
        exposition.contains("sfs_sweeper_removed_total"),
        "the sweeper counter is served"
    );
    assert_eq!(
        series("sfs_active_shares "),
        Some(1),
        "the new share is live"
    );
    assert_eq!(
        series("sfs_stored_bytes "),
        Some(i64::try_from(blob_len)?),
        "stored bytes equals the blob on the volume"
    );
    assert_eq!(
        series("sfs_sweeper_removed_total "),
        Some(0),
        "no sweeper pass ran here"
    );
    let _ = tokio::fs::remove_dir_all(&state.config.data_dir).await;
    Ok(())
}

/// The SSRF guard: with `SFS_IMPORT_ALLOW_PRIVATE_URLS` off, an import
/// from a loopback upstream is refused before any bytes move, the
/// error names the opt-in, and nothing is stored. The upstream runs
/// and is reachable — the refusal is about its address, not its
/// availability.
#[tokio::test]
async fn ssrf_guard_refuses_private_imports() -> Result<(), Box<dyn Error>> {
    let Some((state, mut app)) = setup_with(false, false).await? else {
        return Ok(());
    };

    let payload = b"private network bytes".to_vec();
    let upstream = axum::Router::new().route(
        "/file.bin",
        axum::routing::get(move || {
            let payload = payload.clone();
            async move { ([(header::CONTENT_TYPE, "text/plain")], payload) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, upstream).await {
            log::error!("upstream test server failed: {error}");
        }
    });

    // The literal form of the host: hyper connects to an IP literal
    // without asking any resolver, so the pre-fetch check is the only
    // door this request goes through.
    let request = serde_json::json!({ "url": format!("http://{addr}/file.bin") });
    let (status, body) = call(
        &mut app,
        authorized(post("/api/v1/shares/url")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&request)?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a loopback import is refused: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        String::from_utf8_lossy(&body).contains("SFS_IMPORT_ALLOW_PRIVATE_URLS"),
        "the refusal names the opt-in: {}",
        String::from_utf8_lossy(&body)
    );

    // The name form: `localhost` resolves to loopback, so the same
    // guard fires on the resolution path too.
    let port = addr.port();
    let request = serde_json::json!({ "url": format!("http://localhost:{port}/file.bin") });
    let (status, body) = call(
        &mut app,
        authorized(post("/api/v1/shares/url")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&request)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        String::from_utf8_lossy(&body).contains("SFS_IMPORT_ALLOW_PRIVATE_URLS"),
        "the by-name refusal names the opt-in: {}",
        String::from_utf8_lossy(&body)
    );

    // Refusal means refusal: no share exists afterwards.
    let (status, body) = call(&mut app, authorized(get("/api/v1/shares")), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    let listed: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(0),
        "a refused import stores nothing"
    );

    let _ = tokio::fs::remove_dir_all(&state.config.data_dir).await;
    Ok(())
}

/// The admin token is compared in constant time and rejects quietly.
#[tokio::test]
async fn wrong_tokens_get_no_details() -> Result<(), Box<dyn Error>> {
    let Some((state, mut app)) = setup().await? else {
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
    let _ = tokio::fs::remove_dir_all(&state.config.data_dir).await;
    Ok(())
}

/// The oversize guard: a share past the configured cap is refused before
/// any of its bytes reach the volume.
#[tokio::test]
async fn oversize_is_refused() -> Result<(), Box<dyn Error>> {
    let Some((state, mut app)) = setup().await? else {
        return Ok(());
    };
    // The cap in this test's config is 1 MB; one data frame of a million
    // bytes plus the encapsulation and metadata frames crosses it while
    // every frame is still individually legal (the per-frame limit is
    // 4 MiB).
    let (sk_seed, rnd) = crypto::new_share_seeds();
    let stream = encrypted_stream(
        &sk_seed,
        &rnd,
        &meta_json("big.bin", "application/octet-stream", 1_000_000),
        &vec![0_u8; 1_000_000],
    )?;
    let (status, _) = call(&mut app, authorized(post("/api/v1/shares")), stream).await?;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    // Refusal means refusal: no blob file was left behind.
    let mut listing = tokio::fs::read_dir(&state.config.data_dir).await?;
    assert!(
        listing.next_entry().await?.is_none(),
        "a refused upload left a file behind"
    );
    let _ = tokio::fs::remove_dir_all(&state.config.data_dir).await;
    Ok(())
}

/// The not-public mode: `NOT_PUBLIC_FACING_TURN_OFF_UPLOAD_TOKEN` set, no
/// upload token. The write paths are open to whatever can reach them,
/// the listing follows the same trust, and the DELETE route is absent
/// exactly as in token mode.
#[tokio::test]
async fn not_public_mode_opens_uploads_only() -> Result<(), Box<dyn Error>> {
    let Some((state, mut app)) = setup_with(true, false).await? else {
        return Ok(());
    };

    // An upload without any Authorization header is accepted.
    let (sk_seed, rnd) = crypto::new_share_seeds();
    let stream = encrypted_stream(
        &sk_seed,
        &rnd,
        &meta_json("lan.txt", "text/plain", 5),
        b"trusted network",
    )?;
    let (status, body) = call(&mut app, post("/api/v1/shares"), stream).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "upload without a token in not-public mode: {}",
        String::from_utf8_lossy(&body)
    );
    let created: Value = serde_json::from_slice(&body)?;
    let id = created
        .get("id")
        .and_then(Value::as_str)
        .ok_or("no id")?
        .to_owned();

    // The listing is open too: no token exists to guard it with.
    let (status, _) = call(&mut app, get("/api/v1/shares"), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK, "the listing follows the same trust");

    // Deletion is not available in this mode either: the route is absent.
    let (status, _) = call(
        &mut app,
        delete(&format!("/api/v1/shares/{id}")),
        Vec::new(),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "no DELETE route in not-public mode"
    );

    // And the share itself lives on: 404 did not delete anything.
    assert_eq!(
        status_of(&mut app, &format!("/s/{id}/meta")).await?,
        StatusCode::OK
    );
    let _ = tokio::fs::remove_dir_all(&state.config.data_dir).await;
    Ok(())
}

/// The control plane deletes by share link, on its own router, with its
/// own token: the page loads without one (a browser cannot attach a
/// header), the API behind it answers nothing without it, the lookup
/// reads the bookkeeping, the delete removes the row and the blob
/// together, and the two doors never accept each other's tokens.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn control_plane_deletes_by_link() -> Result<(), Box<dyn Error>> {
    let Some(state) = setup_state(false, true, CONTROL_TOKEN.to_owned()).await? else {
        return Ok(());
    };
    let mut app = router::app(state.clone());
    let mut control = control::control_router(state.clone());

    // A share exists, created through the public write path.
    let (sk_seed, rnd) = crypto::new_share_seeds();
    let plaintext = b"material for the control-plane test".to_vec();
    let stream = encrypted_stream(
        &sk_seed,
        &rnd,
        &meta_json("control.txt", "text/plain", plaintext.len() as u64),
        &plaintext,
    )?;
    let (status, body) = call(&mut app, authorized(post("/api/v1/shares")), stream).await?;
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
        .ok_or("no id")?
        .to_owned();
    assert!(
        tokio::fs::try_exists(blob_path(&state.config.data_dir, &id)).await?,
        "the blob is on the volume"
    );

    // The full link, exactly as a recipient would hold it.
    let link = serde_json::json!({ "link": format!("{BASE_URL}/s/{id}#key=x") });

    // The control door answers only its own token: no header, the
    // upload token, garbage — all 401. The upload token working here
    // would collapse the two doors into one.
    for token in [None, Some(ADMIN_TOKEN), Some("nope")] {
        let mut builder = post("/lookup");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let (status, body) = call(&mut control, builder, serde_json::to_vec(&link)?).await?;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "wrong control token: {}",
            String::from_utf8_lossy(&body)
        );
    }
    // The portal loads in a plain browser: GET / carries no token and
    // still answers the page, dressed in the same headers. A browser
    // navigation cannot attach an Authorization header, so the page is
    // a form, not a secret — the token is typed into it.
    let response = control
        .clone()
        .oneshot(get("/").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY),
        "the page is dressed like every public answer"
    );
    let page = response.into_body().collect().await?.to_bytes();
    assert!(
        String::from_utf8_lossy(&page).contains("Control token"),
        "the page serves without a token"
    );
    // The script the page links loads the same way, or the browser
    // flow would still be dead.
    let (status, body) = call(&mut control, get("/assets/control.js"), Vec::new()).await?;
    assert_eq!(status, StatusCode::OK);
    assert!(
        String::from_utf8_lossy(&body).contains("callControlPlane"),
        "the portal script serves without a token"
    );
    // The API routes keep the gate — the loop above already proved a
    // tokenless lookup gets nothing — and the gate sits inside the
    // security headers.
    let response = control
        .clone()
        .oneshot(post("/lookup").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY),
        "the 401 is dressed like every public answer"
    );

    // Separation of duties, the other direction: the data plane does
    // not accept the control token either.
    let (status, _) = call(
        &mut app,
        Request::builder()
            .method(Method::GET)
            .uri("/api/v1/shares")
            .header(header::AUTHORIZATION, format!("Bearer {CONTROL_TOKEN}")),
        Vec::new(),
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "the control token does not open the data plane"
    );

    // Lookup by the full link: the fragment is cut away, the row is
    // found, and no upload token was involved anywhere above.
    let (status, body) = call(
        &mut control,
        control_authorized(post("/lookup")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&link)?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "lookup: {}",
        String::from_utf8_lossy(&body)
    );
    let record: Value = serde_json::from_slice(&body)?;
    assert_eq!(record.get("id").and_then(Value::as_str), Some(id.as_str()));
    assert_eq!(record.get("one_time").and_then(Value::as_bool), Some(false));
    assert_eq!(record.get("downloads").and_then(Value::as_i64), Some(0));
    assert!(
        record
            .get("stored_size")
            .and_then(Value::as_i64)
            .is_some_and(|size| size > 0),
        "the lookup answers the stored size"
    );
    assert!(record.get("created_at").is_some() && record.get("expires_at").is_some());

    // The path form and the bare id parse to the same share.
    for form in [format!("/s/{id}"), id.clone()] {
        let request = serde_json::json!({ "link": form });
        let (status, body) = call(
            &mut control,
            control_authorized(post("/lookup")).header(header::CONTENT_TYPE, "application/json"),
            serde_json::to_vec(&request)?,
        )
        .await?;
        assert_eq!(status, StatusCode::OK, "link form: {form}");
        let by_form: Value = serde_json::from_slice(&body)?;
        assert_eq!(by_form.get("id").and_then(Value::as_str), Some(id.as_str()));
    }

    // A link whose id would contain a '/' is a 400, and an unknown id
    // is a 404: the operator learns the paste was wrong, and a scan
    // learns nothing.
    let bad = serde_json::json!({ "link": format!("{BASE_URL}/s/{id}/extra") });
    let (status, _) = call(
        &mut control,
        control_authorized(post("/lookup")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&bad)?,
    )
    .await?;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let unknown = serde_json::json!({ "link": format!("{BASE_URL}/s/does-not-exist") });
    let (status, _) = call(
        &mut control,
        control_authorized(post("/lookup")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&unknown)?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Delete: the row and the blob go together, and the answer is the
    // bookkeeping that stopped existing.
    let (status, body) = call(
        &mut control,
        control_authorized(post("/delete")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&link)?,
    )
    .await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "delete: {}",
        String::from_utf8_lossy(&body)
    );
    let deleted: Value = serde_json::from_slice(&body)?;
    assert_eq!(
        deleted.get("id").and_then(Value::as_str),
        Some(id.as_str()),
        "the delete answers the deleted bookkeeping"
    );

    // The public side forgot the share, and the volume lost the blob.
    assert_eq!(
        status_of(&mut app, &format!("/s/{id}/meta")).await?,
        StatusCode::NOT_FOUND
    );
    assert!(
        !tokio::fs::try_exists(blob_path(&state.config.data_dir, &id)).await?,
        "the blob file went with the row"
    );

    // A second delete finds nothing: 404, not a repeat.
    let (status, _) = call(
        &mut control,
        control_authorized(post("/delete")).header(header::CONTENT_TYPE, "application/json"),
        serde_json::to_vec(&link)?,
    )
    .await?;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let _ = tokio::fs::remove_dir_all(&state.config.data_dir).await;
    Ok(())
}
