# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Fixed
- `MLKem::Hybrid.server_respond` / `.client_finish` leaked a bare
  `OpenSSL::PKey::PKeyError` instead of the module's own documented
  `Hybrid::Error` when a peer's X25519 share was a degenerate low-order
  point (RFC 7748 §6.1 — the all-zero raw value being the simplest case).
  Reproduced live pre-fix: a malicious `client_share`/`server_share` with
  an all-zero X25519 component crashed both entry points with an
  undocumented exception type, breaking the same "malformed peer input
  raises `Hybrid::Error`" contract `test_rejects_wrong_size_shares_with_a_clear_error`
  already covers for wrong-size shares. Fixed by wrapping the X25519
  `derive` calls and re-raising as `Hybrid::Error`; added
  `test_server_respond_rejects_degenerate_x25519_client_share` and
  `test_client_finish_rejects_degenerate_x25519_server_share`, covering
  both the all-zero and value-`1` low-order points at both entry points.

### Added
- **Demo recording** (`demo/ml-kem-rb-demo.cast`, linked from the README): a real `irb` session — ML-KEM-768 keygen/encaps/decaps with matching shared secrets, a tampered ciphertext showing FIPS 203's implicit rejection (no exception, a different deterministic secret comes back instead), and the `MLKem::Hybrid` X25519+ML-KEM-768 handshake. Recorded against the real gem, replayed to confirm before committing.
