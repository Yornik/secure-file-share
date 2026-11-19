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
//! the operator importing from sources the operator chose.
//!
//! The fetch is guarded anyway: the import client connects only to
//! public addresses, so a token holder cannot aim the server at its
//! own networks — the database, a cluster service, the cloud metadata
//! address. The operator opts in to private sources (a trusted tailnet,
//! say) with `SFS_IMPORT_ALLOW_PRIVATE_URLS`.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use axum::{Json, extract::State, http::HeaderMap};
use bytes::BytesMut;
use futures::StreamExt;
use serde::{Deserialize, Serialize};

use crate::{
    crypto::{self, CHUNK_PLAINTEXT},
    error::AppError,
    handlers::{ImportResponse, require_upload_token},
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
/// always fits the metadata chunk with room to spare. 120, not 200: it is
/// a display label, not a filesystem promise, and every platform that
/// matters has real limits well under 200. `static/app.js` truncates to
/// the same number for browser uploads, so both paths agree.
fn sanitize_name(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_control() && *c != '/' && *c != '\\')
        .take(120)
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

// ---------------------------------------------------------------------------
// The import guard
//
// A URL import tells the server to fetch, which is exactly what an
// attacker who wants the server to reach its own networks needs. The
// guard keeps the fetch on public address space: the pre-fetch check
// refuses a request whose host is not public (with the opt-in named in
// the error), and the client's resolver re-validates every hostname at
// connect time, so the check and the connection cannot disagree in an
// attacker's favor. DNS rebinding — public answer for the check,
// private answer for the connect — dies in the resolver's filter.
// ---------------------------------------------------------------------------

/// True when `ip` is an address a public host can hold: the address
/// space an import may connect to. Loopback, RFC 1918 and CGNAT space,
/// link-local (which carries the cloud metadata service on
/// 169.254.169.254), benchmarking, multicast and reserved blocks are the
/// server's own world, not public sources. The table refuses heavy on
/// purpose: refusing a rare legitimate address costs the operator one
/// opt-in, while a missing line here would turn the import endpoint
/// into a probe of the server's inside networks.
pub fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped (::ffff:0:0/96) is v4 space in v6 form; unwrap
            // it, so ::ffff:127.0.0.1 answers the v4 rules instead of
            // slipping past the v6 checks.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            is_public_v6(v6)
        }
    }
}

/// The v4 half of the guard's table. Each line names the block it
/// refuses; these are the ranges that never carry a public host.
// Single-letter bindings on purpose: `a`, `b`, `c` are the address
// octets, and the checks below read like the CIDR blocks they quote.
#[allow(clippy::min_ident_chars)]
fn is_public_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    !(a == 0 // 0.0.0.0/8, "this network"
        || a == 10 // 10.0.0.0/8, RFC 1918
        || a == 100 && (64..=127).contains(&b) // 100.64.0.0/10, CGNAT
        || a == 127 // 127.0.0.0/8, loopback
        || a == 169 && b == 254 // 169.254.0.0/16, link-local + cloud metadata
        || a == 172 && (16..=31).contains(&b) // 172.16.0.0/12, RFC 1918
        || a == 192 && b == 0 && c == 0 // 192.0.0.0/24, IETF protocol assignments
        || a == 192 && b == 168 // 192.168.0.0/16, RFC 1918
        || a == 198 && (18..=19).contains(&b) // 198.18.0.0/15, benchmarking
        || (224..=239).contains(&a) // 224.0.0.0/4, multicast
        || (240..=255).contains(&a)) // 240.0.0.0/4, reserved + broadcast
}

/// The v6 half of the guard's table. IPv4-mapped addresses never reach
/// this: the v4 half decided them.
// Single-letter bindings on purpose: `a`..`f` are the address
// segments, and the checks below read like the CIDR blocks they quote.
#[allow(clippy::min_ident_chars, clippy::many_single_char_names)]
fn is_public_v6(v6: Ipv6Addr) -> bool {
    // `::` is unspecified and `::1` is loopback; std names these two,
    // and no range table spells them shorter.
    if v6.is_unspecified() || v6.is_loopback() {
        return false;
    }
    let [a, b, c, d, e, f, _, _] = v6.segments();
    // fc00::/7 is unique-local, fe80::/10 is link-local, ff00::/8 is
    // multicast. 64:ff9b::/96 is the NAT64 well-known prefix: it wraps
    // an IPv4 address, and decoding it would rebuild the v4 rules one
    // layer down, so the whole prefix is not public. A deployment that
    // imports through NAT64 opts in like any other private network.
    !((0xfc00..=0xfdff).contains(&a)
        || (0xfe80..=0xfeff).contains(&a)
        || (0xff00..=0xffff).contains(&a)
        || a == 0x64 && b == 0xff9b && (c | d | e | f) == 0)
}

/// `Url::host_str` brackets an IPv6 literal; the address parse and the
/// resolver want it bare.
fn unbracketed(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

/// The address a literal host names, or `None` when the host is a
/// name. The redirect policy needs this: hyper connects to a literal
/// host without asking the validating resolver, so the policy checks
/// literals itself.
fn literal_ip(host: &str) -> Option<IpAddr> {
    unbracketed(host).parse().ok()
}

/// Resolve `host` with port 0, like reqwest's own `GaiResolver`: the
/// platform needs a port to answer, the caller wants only the
/// addresses, and hyper swaps the real port in afterwards.
async fn resolve_addrs(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host((host, 0)).await?.collect())
}

/// `resolve_addrs` minus every address the guard refuses.
async fn public_addrs(host: &str) -> std::io::Result<Vec<SocketAddr>> {
    Ok(resolve_addrs(host)
        .await?
        .into_iter()
        .filter(|addr| is_public_ip(addr.ip()))
        .collect())
}

/// The front door of the guard: refuse, before any bytes move, an
/// import URL whose host is not on public address space. The client's
/// resolver re-validates every hostname again at connect time, so this
/// check and the connection cannot disagree in an attacker's favor.
/// Literal addresses are decided here alone, because hyper connects to
/// a literal without asking any resolver.
async fn ensure_public_host(url: &reqwest::Url, allow_private: bool) -> Result<(), AppError> {
    if allow_private {
        return Ok(());
    }
    let host = url.host_str().map_or_default(unbracketed);
    let importable = match literal_ip(host) {
        Some(ip) => is_public_ip(ip),
        None => match public_addrs(host).await {
            // A name that answers with nothing public is the guard's
            // refusal case. A name that does not resolve at all is not:
            // the fetch reports that exactly as it always has, and the
            // resolver inside the client re-validates whatever it later
            // resolves to, so falling through cannot reach a private
            // address.
            Ok(addrs) => !addrs.is_empty(),
            Err(_) => true,
        },
    };
    if importable {
        return Ok(());
    }
    log::warn!("refused an import from the non-public host {host}");
    Err(AppError::BadRequest(format!(
        "the import URL points at a non-public host ({host}); set \
         SFS_IMPORT_ALLOW_PRIVATE_URLS=1 to import from a trusted private network"
    )))
}

pub async fn import_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, AppError> {
    if !state.config.not_public_facing_turn_off_upload_token {
        require_upload_token(&headers, &state)?;
    }
    let url = reqwest::Url::parse(&request.url)
        .map_err(|error| AppError::BadRequest(format!("not a valid URL: {error}")))?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return Err(AppError::BadRequest(
            "only http and https URLs can be imported".into(),
        ));
    }
    // Front door of the guard, before any bytes move; the short log
    // line and the opt-in message both live in `ensure_public_host`.
    if let Err(error) = ensure_public_host(&url, state.config.import_allow_private_urls).await {
        Metrics::incr(&state.metrics.imports_err);
        return Err(error);
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
    let (sk_seed, rnd) = crypto::new_share_seeds();
    let (kem_ct, file_key) = crypto::kem_encapsulate(&sk_seed, &rnd);

    let (mut writer, id, expires_at) =
        ShareWriter::begin(&state.pool, &state.config.data_dir, one_time, ttl_days).await?;
    let imported = encrypt_stream(
        &mut writer,
        &kem_ct,
        &file_key,
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
    // The unlock material: the ML-KEM seed regenerates the keypair, the
    // random value carries the other half of the hybrid. Never logged,
    // never stored anywhere but the response.
    let mut unlock = Vec::with_capacity(crypto::FRAGMENT_LEN);
    unlock.extend_from_slice(&sk_seed);
    unlock.extend_from_slice(&rnd);
    let link = format!(
        "{}/s/{}#key={}",
        state.config.base_url,
        id,
        crypto::encode_b64_url(&unlock)
    );
    log::info!("imported share {id} from {url}");
    Ok(Json(ImportResponse {
        id,
        url: link,
        expires_at,
    }))
}

/// Box an address list the way the resolver API wants it.
fn boxed_addrs(addrs: Vec<SocketAddr>) -> reqwest::dns::Addrs {
    Box::new(addrs.into_iter())
}

/// The DNS resolver the import client runs on. It answers only with
/// addresses `is_public_ip` accepted, so reqwest connects to an address
/// this module validated and to nothing else. That is what closes DNS
/// rebinding: a name server can answer the pre-fetch check with a
/// public address and the connect with a private one, and the connect
/// still refuses, because the client dials exactly what the resolver
/// returned. With `allow_private` the filter is off: the operator said
/// the sources are trusted.
struct ValidatingResolver {
    allow_private: bool,
}

impl reqwest::dns::Resolve for ValidatingResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        let allow_private = self.allow_private;
        Box::pin(async move {
            let addrs = resolve_addrs(&host).await?;
            if allow_private {
                return Ok(boxed_addrs(addrs));
            }
            let public: Vec<_> = addrs
                .into_iter()
                .filter(|addr| is_public_ip(addr.ip()))
                .collect();
            if public.is_empty() {
                // Refuse with the opt-in named, rather than hand the
                // connector an empty set it would report as a bare
                // lookup failure: this is a policy decision.
                return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "{host} resolves to no public address; \
                     SFS_IMPORT_ALLOW_PRIVATE_URLS=1 opts in for trusted private networks"
                )));
            }
            Ok(boxed_addrs(public))
        })
    }
}

/// The import client's redirect policy: three hops, like before, with
/// one addition when the guard is on. A redirect hop whose host is a
/// literal IP never reaches the validating resolver — hyper connects to
/// a literal without resolving it — so the policy refuses a hop to a
/// literal non-public address itself. Hostname hops need no help: they
/// resolve through `ValidatingResolver` exactly like the first request.
fn redirect_policy(allow_private: bool) -> reqwest::redirect::Policy {
    if allow_private {
        return reqwest::redirect::Policy::limited(3);
    }
    reqwest::redirect::Policy::custom(|attempt| {
        if let Some(ip) = attempt.url().host_str().and_then(literal_ip)
            && !is_public_ip(ip)
        {
            return attempt.error(
                "the redirect target is a non-public address; \
                 SFS_IMPORT_ALLOW_PRIVATE_URLS=1 opts in for trusted private networks",
            );
        }
        // `limited(3)` in the flesh: `previous` starts with the original
        // URL, so a fourth hop sees four entries.
        if attempt.previous().len() > 3 {
            attempt.error("too many redirects")
        } else {
            attempt.follow()
        }
    })
}

/// The shared HTTP client for URL imports: pooled connections, a
/// 10-second connect timeout, a three-redirect cap — and the guard,
/// installed as the client's resolver so every hostname the import
/// touches, first hop and redirect hops alike, resolves through it.
/// Building this client cannot fail short of a broken TLS setup, which
/// would fail every fetch anyway; a process that cannot build it cannot
/// serve imports, so it stops with the same log line it always had.
pub fn http_client(allow_private: bool) -> reqwest::Client {
    let builder = reqwest::Client::builder()
        .redirect(redirect_policy(allow_private))
        .connect_timeout(Duration::from_secs(10))
        .dns_resolver(ValidatingResolver { allow_private });
    match builder.build() {
        Ok(http) => http,
        Err(error) => {
            log::error!("HTTP client construction failed: {error}");
            std::process::exit(1);
        }
    }
}

/// Stream the upstream body through the encryptor, frame by frame, so the
/// process holds at most one 4 MiB chunk of plaintext at a time. Frame 0 is
/// the encapsulation, handed through untouched; frame 1 is the metadata;
/// the cap is counted on plaintext bytes, before encryption, exactly like
/// the browser path counts ciphertext.
async fn encrypt_stream(
    writer: &mut ShareWriter<'_>,
    kem_ct: &[u8; crypto::KEM_CT_LEN],
    key: &[u8; crypto::KEY_LEN],
    meta: &[u8],
    response: reqwest::Response,
    cap: u64,
) -> Result<(), AppError> {
    writer.add_frame(kem_ct.to_vec()).await?;
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

#[cfg(test)]
mod tests {
    use std::{error::Error, net::IpAddr};

    use super::is_public_ip;

    /// The guard's decision table at its boundaries: an address inside
    /// every refused block, and — where a block is narrow — a public
    /// address on each side of it. If a range ever moves, a boundary
    /// here moves with it or fails loudly.
    #[test]
    fn ip_boundaries() -> Result<(), Box<dyn Error>> {
        let refused = [
            // v4: one address in every block the guard refuses.
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.1.2.3",
            "169.254.169.254",
            "172.16.0.1",
            "172.31.255.255",
            "192.0.0.53",
            "192.168.1.1",
            "198.18.0.1",
            "198.19.255.255",
            "224.0.0.1",
            "239.1.2.3",
            "240.1.2.3",
            "255.255.255.255",
            // v6: unspecified, loopback, unique-local, link-local,
            // multicast, NAT64, and IPv4-mapped forms of refused v4.
            "::",
            "::1",
            "fc00::1",
            "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "fe80::1",
            "ff02::1",
            "64:ff9b::8.8.8.8",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
        ];
        let public = [
            "1.1.1.1",
            "8.8.8.8",
            // The public neighbours of the narrow blocks.
            "100.63.255.255",
            "100.128.0.0",
            "172.15.255.255",
            "172.32.0.0",
            "198.17.255.255",
            "198.20.0.0",
            "2606:4700:4700::1111",
            "::ffff:1.1.1.1",
        ];
        for raw in refused {
            let ip: IpAddr = raw.parse().map_err(|error| format!("{raw}: {error}"))?;
            assert!(!is_public_ip(ip), "{raw} must be refused");
        }
        for raw in public {
            let ip: IpAddr = raw.parse().map_err(|error| format!("{raw}: {error}"))?;
            assert!(is_public_ip(ip), "{raw} must be public");
        }
        Ok(())
    }
}
