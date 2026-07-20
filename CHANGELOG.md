# Changelog

All notable changes to this project will be documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · versioning: [SemVer](https://semver.org/).

## [0.2.0] — 2026-07-20

PQC-domain sprint: hybrid classical+PQ key exchange, the real-world
transition pattern Chrome/Cloudflare/OpenSSH have already deployed, ahead
of NSA CNSA 2.0's Jan 2027 mandate.

### Added
- `MLKem::Hybrid` (`lib/ml_kem/hybrid.rb`): X25519 + ML-KEM-768 hybrid key
  exchange per draft-ietf-tls-ecdhe-mlkem-05 (the TLS 1.3
  `X25519MLKEM768` group). `client_init` / `server_respond` /
  `client_finish`, wire-exact byte layout (1216-byte client share,
  1120-byte server share, 64-byte `ss_mlkem || x25519_ss` shared secret —
  verified against the draft's normative text, ML-KEM's secret ordered
  first as that draft specifies). X25519 via the `openssl` stdlib gem, not
  hand-rolled. `Hybrid.available?` / `Hybrid::Unavailable` handle the real
  compatibility gap: Ruby 3.0's *bundled* openssl gem (2.2.2) has no
  X25519 `PKey` support at all, though this project's floor is Ruby ≥ 3.0
  — every `Hybrid` method fails with a clear, actionable error there
  instead of a raw `NoMethodError`; `test/test_hybrid.rb` skips cleanly
  (not silently, not a hard failure) on 3.0, verified across the full CI
  matrix locally (3.0 skips, 3.1/3.2/3.3/3.4 all pass).
- CI: `test/test_hybrid.rb` added to the existing Ruby-matrix test step.

### Fixed
- README said FIPS 140-2 certificates "went historical in September
  2026" in past tense; that date is Sept 21, 2026 and hadn't happened yet
  as of this release. Corrected to present/future framing with the exact
  date and source (CMVP Historical status).

Verified with real local Ruby (via Docker, since this machine's system
Ruby is 2.6.10 and the gem itself needs endless-method syntax): full test
suite green across the CI matrix, `gem build` clean, a differential test
independently rebuilding each half of the combined secret with the plain
(non-hybrid) primitives to confirm the combiner concatenates rather than
scrambling anything, and a tamper test confirming a flipped server-share
byte changes the derived secret.

## [0.1.0] — 2026-07-16

Initial release.

### Added
- Pure-Ruby ML-KEM (FIPS 203 final): ML-KEM-512/768/1024 — `keygen`/`encaps`/`decaps` plus deterministic `keygen_derand`/`encaps_derand` for KATs.
- Pure-Ruby Keccak-f[1600] core: SHA3-256, SHA3-512, SHAKE128/256 with incremental multi-absorb/multi-squeeze XOF (`MLKem::Keccak::Xof`). Round constants and rho offsets computed from FIPS 202 definitions.
- FIPS 203 input validation: ek modulus check, dk hash check, length checks (`MLKem::Error`); implicit rejection for invalid ciphertexts (never raises).
- Verification: final-FIPS-203 KATs (post-quantum-cryptography/KAT) across all sets; C2SP/CCTV ML-KEM-768 intermediate vector (draft semantics, exact shared-secret match); accumulated pq-crystals runs (10,000 cycles × 3 sets in CI, single-hash comparison vs published constants); differential Keccak tests vs OpenSSL.
- CI: Ruby 3.0–3.4 matrix, accumulated-vector job, gem build job.
