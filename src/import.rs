//! URL import: the server takes over the uploader's role for a file that
//! is not on this machine. It fetches the URL, encrypts the stream with a
//! fresh key exactly the way the browser does, and hands back the complete
//! share link.
//!
//! The zero-knowledge property is deliberately different here and the
//! README says so: during an import the plaintext transits this process
//! once (that is what "import from URL" means), and the key exists in this
//! process's memory until it is returned inside the link. What the database
//! stores is still only ciphertext, and a browser upload still never
//! touches plaintext here. The endpoint requires the admin token; it is
//! the operator importing from sources the operator chose — including
//! tailnet addresses, which a public URL-fetcher would be right to refuse.

use axum::{Json, extract::State, http::HeaderMap};
use bytes::BytesMut;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{self, CHUNK_PLAINTEXT},
    error::AppError,
    handlers::{ImportResponse, require_admin},
    state::{AppState, Metrics, ShareWriter, clamp_ttl},
};

#[derive(Deserialize)]
pub struct ImportRequest {
    url: String,
    ttl_days: Option<i64>,
    one_time: Option<bool>,
}

/// The metadata chunk's plaintext, byte-identical to what the JavaScript
/// writes: name, MIME type and (when the upstream announces it) size.
#[derive(Serialize)]
struct MetaJson {
    name: String,
    mime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

/// Percent-decode a URL path segment. `%20` becomes a space; a `%` that is
/// not followed by two hex digits stays a literal `%`. Lossy on invalid
/// UTF-8: a name that cannot decode still makes a usable label.
fn percent_decode(segment: &str) -> String {
    let mut out = Vec::with_capacity(segment.len());
    let mut bytes = segment.as_bytes().iter().copied();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        match (bytes.next(), bytes.next()) {
            (Some(hi), Some(lo))
                if (hi as char).is_ascii_hexdigit() && (lo as char).is_ascii_hexdigit() =>
            {
                let hi = (hi as char).to_digit(16).unwrap_or_default();
                let lo = (lo as char).to_digit(16).unwrap_or_default();
                // Two hex digits cannot exceed 255, so this cannot fail.
                out.push(u8::try_from(hi * 16 + lo).unwrap_or_default());
            }
            (Some(hi), Some(lo)) => {
                out.extend_from_slice(&[b'%', hi, lo]);
            }
            _ => out.push(b'%'),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Strip path separators and control characters, keep it to a length that
/// always fits the metadata chunk with room to spare.
fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .take(200)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// `filename=` from a Content-Disposition header, quotes stripped.
fn disposition_filename(headers: &reqwest::header::HeaderMap) -> Option<String> {
    let raw = headers
        .get(reqwest::header::CONTENT_DISPOSITION)?
        .to_str()
        .ok()?;
    let value = raw
        .split(';')
        .find_map(|part| part.trim().strip_prefix("filename="))?
        .trim()
        .trim_matches('"');
    let name = sanitize_name(value);
    (!name.is_empty()).then_some(name)
}

/// The last path segment of the URL, percent-decoded.
fn url_filename(url: &reqwest::Url) -> Option<String> {
    let segment = percent_decode(url.path_segments()?.next_back()?);
    let name = sanitize_name(&segment);
    (!name.is_empty()).then_some(name)
}

pub async fn import_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, AppError> {
    require_admin(&headers, &state)?;
    let url = reqwest::Url::parse(&request.url)
        .map_err(|error| AppError::BadRequest(format!("not a valid URL: {error}")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(AppError::BadRequest(
            "only http and https URLs can be imported".into(),
        ));
    }
    let ttl_days = clamp_ttl(&state.config, request.ttl_days);
    let one_time = request.one_time.unwrap_or(false);

    let response = state.http.get(url.clone()).send().await.map_err(|error| {
        Metrics::incr(&state.metrics.imports_err);
        AppError::Import(format!("fetch failed: {error}"))
    })?;
    let status = response.status();
    if !status.is_success() {
        Metrics::incr(&state.metrics.imports_err);
        return Err(AppError::Import(format!("upstream answered {status}")));
    }
    let mime = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map_or_else(|| "application/octet-stream".into(), str::to_owned);
    let name = disposition_filename(response.headers())
        .or_else(|| url_filename(&url))
        .unwrap_or_else(|| "download".into());
    let meta = MetaJson {
        name,
        mime,
        size: response.content_length(),
    };
    let meta_bytes = serde_json::to_vec(&meta).map_err(|error| {
        log::error!("metadata serialization failed: {error}");
        AppError::Internal("meta".into())
    })?;
    let key = crypto::new_key();

    let (mut writer, id, expires_at) = ShareWriter::begin(&state.pool, one_time, ttl_days).await?;
    let imported = encrypt_stream(
        &mut writer,
        &key,
        &meta_bytes,
        response,
        state.config.import_max_bytes,
    )
    .await;
    if let Err(error) = imported {
        Metrics::incr(&state.metrics.imports_err);
        return Err(error);
    }
    writer.finish().await?;
    Metrics::incr(&state.metrics.imports_ok);
    let link = format!(
        "{}/s/{}#key={}",
        state.config.base_url,
        id,
        crypto::encode_b64_url(&key)
    );
    log::info!("imported share {id} from {url}");
    Ok(Json(ImportResponse {
        id,
        url: link,
        expires_at,
    }))
}

/// Stream the upstream body through the encryptor, frame by frame, so the
/// process holds at most one 4 MiB chunk of plaintext at a time. The cap is
/// counted on plaintext bytes, before encryption, exactly like the browser
/// path counts ciphertext.
async fn encrypt_stream(
    writer: &mut ShareWriter<'_>,
    key: &[u8; crypto::KEY_LEN],
    meta: &[u8],
    response: reqwest::Response,
    cap: u64,
) -> Result<(), AppError> {
    let nonce = crypto::new_nonce();
    let frame = crypto::encrypt_chunk(key, &nonce, meta)
        .map_err(|_| AppError::Internal("encrypt".into()))?;
    writer.add_frame(frame).await?;

    let mut stream = response.bytes_stream();
    let mut buf = BytesMut::new();
    let mut total = meta.len() as u64;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|error| AppError::Import(format!("upstream stream failed: {error}")))?;
        buf.extend_from_slice(&chunk);
        total += chunk.len() as u64;
        if total > cap {
            return Err(AppError::TooLarge { limit: cap });
        }
        while buf.len() >= CHUNK_PLAINTEXT {
            let piece = buf.split_to(CHUNK_PLAINTEXT);
            let nonce = crypto::new_nonce();
            let frame = crypto::encrypt_chunk(key, &nonce, &piece)
                .map_err(|_| AppError::Internal("encrypt".into()))?;
            writer.add_frame(frame).await?;
        }
    }
    if !buf.is_empty() {
        let nonce = crypto::new_nonce();
        let frame = crypto::encrypt_chunk(key, &nonce, &buf)
            .map_err(|_| AppError::Internal("encrypt".into()))?;
        writer.add_frame(frame).await?;
    }
    // The empty end-of-stream marker, so a truncated upstream cannot look
    // like a complete share on the other side.
    let nonce = crypto::new_nonce();
    let marker = crypto::encrypt_chunk(key, &nonce, &[])
        .map_err(|_| AppError::Internal("encrypt".into()))?;
    writer.add_frame(marker).await?;
    Ok(())
}
