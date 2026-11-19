//! The only cryptography this server performs is for URL imports, where it
//! takes the role of the uploader's browser: fresh seeds, an encapsulation,
//! per-chunk encryption, and the unlock material handed back in the share
//! link's fragment. Browser uploads arrive already encrypted and this
//! module is never called for them.
//!
//! The wire format v2 (identical in the JavaScript in `static/`):
//!
//! ```text
//! frame 0:            ML-KEM-1024 ciphertext (raw, exactly 1568 bytes)
//! frame 1:            encrypted metadata chunk (JSON, <= 64 KiB plaintext)
//! frames 2..n:        encrypted data chunks (<= 4 MiB plaintext each)
//! final frame:        an empty encrypted chunk (just nonce and tag)
//! encrypted chunk:    nonce (12) || AES-256-GCM ciphertext || tag
//! frame on the wire:  u32 big-endian length || chunk
//! unlock fragment:    base64url( sk_seed 64 || rnd 32 )
//! ```
//!
//! The file key is hybrid: K = HKDF-SHA256( `mlkem_shared_secret` || rnd ).
//! An attacker who breaks ML-KEM-1024 still faces a 256-bit random value;
//! an attacker who brute-forces the 256-bit random value still faces
//! ML-KEM-1024. This is the same "both must break" shape the browser vendors
//! use for their X25519+ML-KEM hybrids, and it is what makes the label
//! "post-quantum" honest here: without a recipient keypair there is no key
//! exchange to attack, so the quantum-relevant claim lands on the
//! encapsulation plus the symmetric core, and both are 128-bit-quantum
//! floors or better.
//!
//! Per-chunk nonces are random 96-bit values, never derived from a counter:
//! one key protects at most a few thousand chunks here (the upload cap
//! bounds it), far below the 2^32 random-nonce collision birthday bound for
//! AES-GCM. The empty final chunk makes truncation fail its tag check, the
//! same trick age's STREAM construction plays.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit, consts::U12},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use ml_kem::{B32, Ciphertext, Decapsulate, Encapsulate, MlKem1024, Seed};
use sha2::Sha256;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// ML-KEM-1024 ciphertext length (FIPS 203): frame 0 is exactly this.
pub const KEM_CT_LEN: usize = 1568;
/// The unlock material carried in the URL fragment: a 64-byte ML-KEM-1024
/// keygen seed (d || z, so the same seed regenerates the same keypair
/// everywhere) plus a 32-byte random value for the hybrid derivation.
pub const SK_SEED_LEN: usize = 64;
pub const RND_LEN: usize = 32;
pub const FRAGMENT_LEN: usize = SK_SEED_LEN + RND_LEN;
/// Upper bound for the metadata chunk's plaintext. Enforced by the frame
/// reader on upload too, so a client cannot park a multi-megabyte "metadata"
/// chunk in frame 1.
pub const META_PLAINTEXT_LIMIT: usize = 64 * 1024;
/// Data chunk size. Small enough that a browser holds at most this much plus
/// one chunk in memory, large enough that the per-frame overhead (16 bytes of
/// nonce and tag per 4 MiB) rounds to nothing.
pub const CHUNK_PLAINTEXT: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("decryption failed")]
pub struct CryptoError;

/// Fresh unlock material for a new share: the ML-KEM seed and the hybrid's
/// random value, both from the OS CSPRNG.
pub fn new_share_seeds() -> ([u8; SK_SEED_LEN], [u8; RND_LEN]) {
    let mut sk_seed = [0_u8; SK_SEED_LEN];
    let mut rnd = [0_u8; RND_LEN];
    // rand::fill draws from the OS CSPRNG; on failure it panics, which is
    // the right failure mode for a process that cannot generate secrets.
    rand::fill(&mut sk_seed);
    rand::fill(&mut rnd);
    (sk_seed, rnd)
}

/// The hybrid file key: both inputs must break for this to fall.
///
/// # Panics
///
/// HKDF with a valid 32-byte output cannot fail; if it does, the panic
/// path leaks no secret.
#[expect(
    clippy::expect_used,
    reason = "HKDF with a valid 32-byte output cannot fail; the panic path leaks no secret"
)]
pub fn hybrid_file_key(shared_secret: &B32, rnd: &[u8; RND_LEN]) -> [u8; KEY_LEN] {
    let mut ikm = Vec::with_capacity(KEY_LEN + RND_LEN);
    ikm.extend_from_slice(shared_secret.as_slice());
    ikm.extend_from_slice(rnd);
    let hk = Hkdf::<Sha256>::new(Some(b"secure-file-share/v2"), &ikm);
    let mut key = [0_u8; KEY_LEN];
    hk.expand(b"file key", &mut key)
        .map_err(|_| CryptoError)
        .expect("hkdf expand 32 bytes");
    key
}

/// The uploader side of the hybrid: encapsulate to the keypair derived from
/// the seed, and derive the file key. Returns (ciphertext, file key).
///
/// # Panics
///
/// Only on conversions between constant sizes this module defines; a
/// failure means the constants stopped agreeing.
#[expect(
    clippy::expect_used,
    reason = "conversions between constant sizes this module defines; a failure means the constants stopped agreeing"
)]
pub fn kem_encapsulate(
    sk_seed: &[u8; SK_SEED_LEN],
    rnd: &[u8; RND_LEN],
) -> ([u8; KEM_CT_LEN], [u8; KEY_LEN]) {
    let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(
        Seed::try_from(sk_seed.as_slice()).expect("constant length"),
    );
    let ek = dk.encapsulation_key();
    // Infallible by the same FIPS 203 argument as decapsulation: the RNG
    // only picks the ephemeral encapsulation seed, never a value the
    // protocol can reject.
    let (ciphertext, shared_secret): (Ciphertext<MlKem1024>, B32) =
        ek.encapsulate_with_rng(&mut rand::rng());
    let key = hybrid_file_key(&shared_secret, rnd);
    let mut ct = [0_u8; KEM_CT_LEN];
    ct.copy_from_slice(ciphertext.as_slice());
    (ct, key)
}

/// The recipient side, used by the tests to prove the stored bytes
/// round-trip; the production download path serves ciphertext untouched.
///
/// # Panics
///
/// Only on conversions between constant sizes this module defines; a
/// failure means the constants stopped agreeing.
#[expect(
    clippy::expect_used,
    reason = "conversions between constant sizes this module defines; a failure means the constants stopped agreeing"
)]
pub fn kem_decapsulate(
    sk_seed: &[u8; SK_SEED_LEN],
    rnd: &[u8; RND_LEN],
    ct: &[u8; KEM_CT_LEN],
) -> [u8; KEY_LEN] {
    let dk = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(
        Seed::try_from(sk_seed.as_slice()).expect("constant length"),
    );
    let ciphertext = Ciphertext::<MlKem1024>::try_from(ct.as_slice()).expect("constant length");
    // Decapsulation is infallible by design (FIPS 203 implicit rejection):
    // a corrupted ciphertext yields a pseudorandom secret, never an error.
    let shared_secret: B32 = dk.decapsulate(&ciphertext);
    hybrid_file_key(&shared_secret, rnd)
}

pub fn new_key() -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    rand::fill(&mut key);
    key
}

pub fn new_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    rand::fill(&mut nonce);
    nonce
}

/// Share id: 16 random bytes, base64url without padding: 22 characters, no
/// `+` or `/`, safe in a URL path, and 128 bits of entropy so the share list
/// cannot be walked.
pub fn new_id() -> String {
    let mut raw = [0_u8; 16];
    rand::fill(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

pub fn encode_b64_url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_b64_url(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    URL_SAFE_NO_PAD.decode(text)
}

/// Encrypt one chunk. Returns nonce-ciphertext-tag, the frame payload.
pub fn encrypt_chunk(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher =
        Aes256Gcm::new(&Key::<Aes256Gcm>::try_from(key.as_slice()).map_err(|_| CryptoError)?);
    let nonce = Nonce::<U12>::try_from(nonce.as_slice()).map_err(|_| CryptoError)?;
    let ciphertext = cipher.encrypt(&nonce, plaintext).map_err(|_| CryptoError)?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt one chunk's nonce-ciphertext-tag. Used by the tests to prove the
/// stored bytes round-trip; the production download path serves ciphertext
/// untouched.
pub fn decrypt_chunk(key: &[u8; KEY_LEN], nonce_ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if nonce_ct.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError);
    }
    let Some((nonce, ciphertext)) = nonce_ct.split_at_checked(NONCE_LEN) else {
        return Err(CryptoError);
    };
    let cipher =
        Aes256Gcm::new(&Key::<Aes256Gcm>::try_from(key.as_slice()).map_err(|_| CryptoError)?);
    let nonce = Nonce::<U12>::try_from(nonce).map_err(|_| CryptoError)?;
    cipher.decrypt(&nonce, ciphertext).map_err(|_| CryptoError)
}
