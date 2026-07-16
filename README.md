# ml_kem — pure-Ruby ML-KEM (FIPS 203)

[![CI](https://github.com/bharat3645/ml-kem-rb/actions/workflows/ci.yml/badge.svg)](https://github.com/bharat3645/ml-kem-rb/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)

**ML-KEM (formerly CRYSTALS-Kyber), the NIST post-quantum key-encapsulation standard, in pure Ruby.** All three parameter sets (ML-KEM-512, -768, -1024), zero runtime dependencies — including the Keccak/SHAKE core, which is implemented here too. Every algorithm is verified against external known-answer tests (details below).

Ruby is heading into the post-quantum transition with almost no native tooling: CNSA 2.0 requires PQC adoption starting 2027, FIPS 140-2 certificates went historical in September 2026, and the Ruby/Rails ecosystem has essentially nothing to even experiment with. This gem exists so Ruby developers can *learn, prototype, and test* ML-KEM today with readable code that follows FIPS 203's algorithm structure line by line.

## Honest security framing — read this first

This is a **KAT-verified reference implementation, not a hardened production library**:

- **Not constant-time.** Ruby's integer arithmetic, GC, and interpreter make timing side-channels unavoidable at this level of the stack. A colocated attacker measuring decapsulation timing could in principle extract key material.
- **No secret zeroization.** Ruby strings holding key material cannot be reliably wiped.
- **Correctness is the claim, and it is tested hard** (see verification section): final-FIPS-203 KATs across all three parameter sets, the C2SP/CCTV intermediate-values vector, 30,000 accumulated pq-crystals test cycles in CI, and a differentially-tested Keccak core.

Appropriate uses: development and testing, protocol prototyping, KAT generation, education, interoperability checks, non-adversarial environments. For production key exchange, use a vetted native implementation (e.g. liboqs bindings or OpenSSL ≥ 3.5 once its ML-KEM lands in your stack) — and file an issue here if you'd like a hardened backend option.

## Install

```console
gem install ml_kem
```

Zero dependencies; Ruby ≥ 3.0. (Not yet published? `gem build ml_kem.gemspec && gem install ml_kem-*.gem`.)

## Usage

```ruby
require 'ml_kem'

kem = MLKem::KEM.new(768)        # 512, 768 (default), or 1024

# Alice generates a key pair and publishes ek
ek, dk = kem.keygen

# Bob encapsulates: derives a shared secret + ciphertext for Alice
shared_secret, ciphertext = kem.encaps(ek)

# Alice decapsulates the same 32-byte shared secret
shared_secret2 = kem.decaps(dk, ciphertext)
shared_secret == shared_secret2  # => true
```

Deterministic variants (for KATs and reproducible tests):

```ruby
ek, dk = kem.keygen_derand(d, z)      # d, z: 32-byte seeds
key, ct = kem.encaps_derand(ek, m)    # m: 32-byte seed
```

Sizes (bytes):

| Set | ek | dk | ct | shared secret |
|---|---|---|---|---|
| ML-KEM-512 | 800 | 1632 | 768 | 32 |
| ML-KEM-768 | 1184 | 2400 | 1088 | 32 |
| ML-KEM-1024 | 1568 | 3168 | 1568 | 32 |

FIPS 203 input validation is implemented: encapsulation-key modulus check, decapsulation-key hash check, and length checks all raise `MLKem::Error`; invalid ciphertexts never raise — they trigger the standard's implicit rejection (a deterministic wrong key), as required.

The SHA-3/SHAKE core is usable on its own — Ruby's stdlib has no SHA-3, so this may be independently useful:

```ruby
MLKem::Keccak.sha3_256(data)          # 32 bytes
MLKem::Keccak.shake256(data, 100)     # any output length
xof = MLKem::Keccak::Xof.new(168)     # incremental SHAKE-128
xof.absorb('chunk 1'); xof.absorb('chunk 2'); xof.squeeze(64)
```

## How it's verified

Correctness claims in crypto are worthless without evidence. The test suite pins this implementation to four independent external sources:

1. **Final FIPS 203 KATs** ([post-quantum-cryptography/KAT](https://github.com/post-quantum-cryptography/KAT)): keygen → encaps → decaps shared-secret matches for all three parameter sets, plus additional ML-KEM-768 vectors. These vectors encode the *final* standard's semantics — including the `G(d‖k)` rank-byte domain separation that changed after the draft.
2. **C2SP/CCTV intermediate values** ([C2SP/CCTV](https://github.com/C2SP/CCTV)): the ML-KEM-768 development vector reproduces `ρ`, `ek`, `dk` prefixes and the exact shared secret. The exact `K` match transitively pins the full encapsulation key byte-for-byte, since `K = G(m ‖ H(ek))[0..32]`.
3. **Accumulated pq-crystals vectors** (CI, per C2SP/CCTV's scheme): a deterministic SHAKE-128 stream drives **10,000 full keygen/encaps/decaps cycles per parameter set** — including implicit-rejection decapsulations of random ciphertexts — and all outputs (`ek`, `dk`, `ct`, both shared secrets) are absorbed into a SHAKE-128 accumulator whose final hash must equal the published constant. One wrong byte anywhere in 30,000 test cycles changes the hash. (These published constants predate the final standard, so the run uses the draft KeyGen variant; the final semantics are covered by #1 — the two differ only in KeyGen's hash input.)
4. **Differential Keccak testing**: the pure-Ruby Keccak-f[1600]/SHA-3/SHAKE core is tested against OpenSSL on hundreds of random inputs per run, plus canonical FIPS 202 vectors and multi-block incremental XOF reads. Round constants and rotation offsets are *computed from their FIPS 202 definitions* at load time, not transcribed.

Run everything locally:

```console
ruby -Ilib test/test_keccak.rb
ruby -Ilib test/test_ml_kem.rb
ruby -Ilib test/accumulated.rb 768 10000 f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3 ipd
```

## Performance

Pure Ruby is not fast crypto and doesn't pretend to be (Ruby 3.0, one core, ML-KEM-768): keygen ≈ 12 ms, encaps ≈ 13 ms, decaps ≈ 16 ms. Three orders of magnitude slower than native implementations; entirely fine for tests, tooling, and prototyping.

## Design notes

The code deliberately mirrors FIPS 203's structure: `SampleNTT`, `SamplePolyCBD`, `NTT`/`NTT⁻¹`, `MultiplyNTTs`, `Compress`/`Decompress`, `ByteEncode`/`ByteDecode`, K-PKE, and the ML-KEM FO transform are each small, named methods you can read next to the standard. The NTT twiddle factors are computed from ζ = 17 and BitRev₇ rather than pasted as magic tables. If you're learning ML-KEM, reading `lib/ml_kem.rb` top to bottom alongside the spec is the intended experience.

## Related tools

Part of a security-tooling suite: [pqc-scan](https://github.com/bharat3645) (PQ-readiness scanner, upcoming), [agent-rules-audit](https://github.com/bharat3645/agent-rules-audit), [mcp-sentinel](https://github.com/bharat3645/mcp-sentinel), [trace2eval](https://github.com/bharat3645/trace2eval).

## License

MIT. Test vectors referenced from C2SP/CCTV are CC0.
