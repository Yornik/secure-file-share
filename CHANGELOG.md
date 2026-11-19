# Changelog

## [0.3.1](https://github.com/Yornik/secure-file-share/compare/v0.3.0...v0.3.1) (2026-11-19)


### Bug Fixes

* **docker:** rebuild the crate after COPY and smoke-test the binary ([61c1b15](https://github.com/Yornik/secure-file-share/commit/61c1b15d1d92c79b05529ae03b49e610510b8746))


### Documentation

* rewrite the README in ASD-STE100 style, trim screenshots, add badges ([5843c83](https://github.com/Yornik/secure-file-share/commit/5843c83d05a6535438c1de1c337ecd14253e18f8))

## [0.3.0](https://github.com/Yornik/secure-file-share/compare/v0.2.0...v0.3.0) (2026-11-19)


### ⚠ BREAKING CHANGES

* wire format v2. Frame 0 is a raw 1568-byte ML-KEM-1024 ciphertext and the fragment carries seed+random, so v0.1 links cannot be opened by v0.2 and vice versa. The share_chunks table is dropped by migration 0002; every v0.1 deployment predates production use, so no rows exist to migrate.

### Features

* hybrid post-quantum encryption and a volume blob backend ([31c5020](https://github.com/Yornik/secure-file-share/commit/31c5020ca45005496045ed29c7ed59c0cac3a20d))

## [0.2.0](https://github.com/Yornik/secure-file-share/compare/v0.1.0...v0.2.0) (2026-11-19)


### Features

* cap file names at 120 characters in both upload paths ([fd42a9c](https://github.com/Yornik/secure-file-share/commit/fd42a9c1eb4a7df043c0e1ea273559c9e6c25e16))


### Documentation

* screenshots in dark mode (the default palette) ([2c0da43](https://github.com/Yornik/secure-file-share/commit/2c0da4356f1c1426cbea4d36353fa848f57aad0c))

## 0.1.0 (2026-11-19)


### Features

* zero-knowledge file sharing — browser-encrypted, chunked, stateless behind Postgres ([4da09d2](https://github.com/Yornik/secure-file-share/commit/4da09d295c001626f2e3a3ebcf8fee6b22a40c21))


### Bug Fixes

* align Cargo.lock with the bootstrap version ([0a01163](https://github.com/Yornik/secure-file-share/commit/0a01163734032e3b221fcb182e279bd312098c68))
* **ci:** runner labels, pg18 service env, CDLA license ([9059340](https://github.com/Yornik/secure-file-share/commit/9059340cac04d784bc7fb4180c2ab141d3b56bb1))
