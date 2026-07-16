# frozen_string_literal: true

# Accumulated pq-crystals vector run (see C2SP/CCTV ML-KEM README).
#
# A deterministic SHAKE-128 RNG (empty input) drives N tests; outputs are
# absorbed into a second SHAKE-128 instance whose final 32-byte squeeze must
# equal a published constant. This exercises keygen/encaps/decaps —
# ciphertexts included — across 10 000 random cases without shipping vectors.
#
# Usage:
#   ruby -Ilib test/accumulated.rb <512|768|1024> <count> <expected-hex> <mode> [budget-seconds]
#     mode: "ipd" (draft-era vectors, matches the published CCTV hashes)
#           or "final" (FIPS 203 final; no published accumulated hashes yet)
#
# If budget-seconds is given, the run checkpoints its full state (both SHAKE
# instances) to test/accumulated-<set>.ckpt when the budget expires and exits
# with status 3; re-running the same command resumes. Exit 0 = PASS, 1 = FAIL.

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)
require 'ml_kem'

strength = Integer(ARGV[0] || 768)
count = Integer(ARGV[1] || 10_000)
expected = ARGV[2]
mode = ARGV[3] || 'ipd'
budget = ARGV[4] ? Float(ARGV[4]) : nil

kem = MLKem::KEM.new(strength)
kem.instance_variable_set(:@ipd_mode, true) if mode == 'ipd'

ckpt_path = File.expand_path("accumulated-#{strength}.ckpt", __dir__)

if File.exist?(ckpt_path)
  rng, acc, start_i, consistency_failures, spent = Marshal.load(File.binread(ckpt_path))
else
  # Sanity: the RNG stream must start with the documented bytes.
  probe = MLKem::Keccak.shake128('', 16).unpack1('H*')
  abort "RNG sanity failed: #{probe}" unless probe == '7f9c2ba4e88f827d616045507605853e'
  rng = MLKem::Keccak::Xof.new(168).absorb('')
  acc = MLKem::Keccak::Xof.new(168).absorb('')
  start_i = 0
  consistency_failures = 0
  spent = 0.0
end

t0 = Time.now
(start_i...count).each do |i|
  if budget && (Time.now - t0) > budget
    File.binwrite(ckpt_path, Marshal.dump([rng, acc, i, consistency_failures, spent + (Time.now - t0)]))
    puts "checkpoint #{i}/#{count} (#{(spent + (Time.now - t0)).round}s total)"
    exit 3
  end

  d = rng.squeeze(32)
  z = rng.squeeze(32)
  m = rng.squeeze(32)
  ct_rand = rng.squeeze(kem.ct_size)

  ek, dk = kem.keygen_derand(d, z)
  k, ct = kem.encaps_derand(ek, m)
  consistency_failures += 1 unless kem.decaps(dk, ct) == k
  k_bad = kem.decaps(dk, ct_rand)

  acc.absorb(ek)
  acc.absorb(dk)
  acc.absorb(ct)
  acc.absorb(k)
  acc.absorb(k_bad)
end

got = acc.squeeze(32).unpack1('H*')
total = (spent + (Time.now - t0)).round
File.delete(ckpt_path) if File.exist?(ckpt_path)
if expected.nil?
  puts "hash=#{got} (#{count} tests, #{total}s, #{consistency_failures} consistency failures)"
elsif got == expected && consistency_failures.zero?
  puts "PASS #{strength}/#{mode}: #{got} (#{count} tests, #{total}s)"
  exit 0
else
  puts "FAIL #{strength}/#{mode}: got #{got}, want #{expected} (#{consistency_failures} consistency failures)"
  exit 1
end
