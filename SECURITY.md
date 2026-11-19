# Security policy

## Supported versions

Only the newest release tag is supported. The running version is on the
image labels and in the `sfs_build_info` metric; if yours is older, update
first and then report.

## Reporting a vulnerability

Use GitHub's "Report a vulnerability" on this repository
(https://github.com/Yornik/secure-file-share/security/advisories), so the
report is private until a fix ships. Please do not open a public issue for
anything you would not paste into a public issue.

## Threat model

The service has exactly two doors, and their promises differ:

- **Browser uploads are zero-knowledge.** The unlock material is generated
  in the browser — a 64-byte ML-KEM-1024 keygen seed and a 256-bit random
  value — the file is encrypted with the hybrid key before it leaves the
  page, and the material travels only in the URL fragment, which browsers
  never send. The server parses frame lengths and stores ciphertext; even
  the file name is inside the encrypted metadata chunk. The key is a
  hybrid: HKDF-SHA256 over the ML-KEM-1024 shared secret and the random
  value, so breaking the KEM alone or guessing the random value alone is
  not enough. Postgres holds only bookkeeping; the volume holds only
  ciphertext bytes; neither ever holds anything that names a file.
- **URL imports are not zero-knowledge for the plaintext, by definition.**
  The endpoint (upload-token only) fetches a file the server can reach and
  encrypts it with a fresh key. During the import the plaintext transits
  the process once; the key exists in process memory until it is returned
  in the link. The database still only ever stores ciphertext. Imports
  refuse private addresses by default; the operator can opt in for a
  trusted tailnet with `SFS_IMPORT_ALLOW_PRIVATE_URLS`, so the fetch cannot
  be aimed at the server's own networks. Documented in the README, on the
  upload form, and in the code (`src/import.rs`).

Operational assumptions:

- One upload token, compared in constant time, no accounts. Anyone holding
  the token can create shares; nobody holding it can delete one, because
  the public API has no deletion path in any mode. Treat the token like a
  password and put it in a SOPS-encrypted secret, never in a manifest in
  the clear.

> [!CAUTION]
> A deployment that no public network can reach may drop the upload
> token (`NOT_PUBLIC_FACING_TURN_OFF_UPLOAD_TOKEN`). The network is then
> the only guard. On a deployment the public internet can reach, the
> switch turns the service into an open file-drop. Strangers store
> malware and illegal material on the operator's domain. The operator
> cannot read what is stored. It is a crime in many countries to host
> such content. Keep the switch off unless the network is private beyond
> doubt. Keep the control token set, so revocation stays possible.
- The database is trusted with bookkeeping and the volume with ciphertext.
  Expiry and burn-after-reading are enforced at claim time in the same
  statement that counts the download, so races cannot double-spend a
  one-time share. A blob file only becomes a share after the whole stream
  validates and fsyncs; a partial upload is a temporary file the sweeper
  removes, and its bookkeeping row rolls back with it.
- No rate limiting is built in (v0.1); the production deployment sits
  behind Traefik's fail2ban middleware. Share ids carry 128 bits of
  entropy, so enumerating them is not a strategy.
- `crypto.subtle` (browser-side AES-GCM) requires a secure context:
  production is HTTPS; local development runs on `localhost`, which is one
  by definition.
- The web UI is embedded in the binary, no CDN and no external script,
  behind a CSP without `unsafe-inline`. There is nothing to subvert from
  outside and nothing to cache.

What this design does not attempt:

- Hiding *that* a share exists, or its size, or its timing, from the
  server or the database.
- Protecting a recipient who pastes a link into a channel that strips
  fragments, or an uploader who shares the link with anyone but the
  intended recipient. The key is the link.
- Multi-tenant anything. One token, one household.
