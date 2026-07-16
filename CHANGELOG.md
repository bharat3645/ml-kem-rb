# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · versioning: [SemVer](https://semver.org/).

## [0.1.0] — 2026-07-16

Initial release.

### Added
- Pure-Ruby ML-KEM (FIPS 203 final): ML-KEM-512/768/1024 — `keygen`/`encaps`/`decaps` plus deterministic `keygen_derand`/`encaps_derand` for KATs.
- Pure-Ruby Keccak-f[1600] core: SHA3-256, SHA3-512, SHAKE128/256 with incremental multi-absorb/multi-squeeze XOF (`MLKem::Keccak::Xof`). Round constants and rho offsets computed from FIPS 202 definitions.
- FIPS 203 input validation: ek modulus check, dk hash check, length checks (`MLKem::Error`); implicit rejection for invalid ciphertexts (never raises).
- Verification: final-FIPS-203 KATs (post-quantum-cryptography/KAT) across all sets; C2SP/CCTV ML-KEM-768 intermediate vector (draft semantics, exact shared-secret match); accumulated pq-crystals runs (10,000 cycles × 3 sets in CI, single-hash comparison vs published constants); differential Keccak tests vs OpenSSL.
- CI: Ruby 3.0–3.4 matrix, accumulated-vector job, gem build job.
