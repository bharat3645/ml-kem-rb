# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/ml_kem/keccak'

class TestKeccak < Minitest::Test
  K = MLKem::Keccak

  def hex(s) = s.unpack1('H*')

  # Canonical FIPS 202 values (also cross-checked against OpenSSL below).
  def test_sha3_256_empty
    assert_equal 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a', hex(K.sha3_256(''))
  end

  def test_sha3_512_empty
    assert_equal 'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6' \
                 '15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26', hex(K.sha3_512(''))
  end

  def test_shake128_empty_prefix
    assert_equal '7f9c2ba4e88f827d616045507605853e', hex(K.shake128('', 16))
  end

  def test_shake256_abc
    assert_equal '483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739', hex(K.shake256('abc', 32))
  end

  def test_round_constants_canonical
    assert_equal 0x0000000000000001, K::RC[0]
    assert_equal 0x0000000000008082, K::RC[1]
    assert_equal 0x800000000000808a, K::RC[2]
    assert_equal 0x8000000080008008, K::RC[23]
  end

  def test_incremental_squeeze_matches_one_shot
    xof = K::Xof.new(168)
    xof.absorb('incremental')
    chunks = +''
    [1, 7, 31, 168, 200, 13].each { |n| chunks << xof.squeeze(n) }
    assert_equal K.shake128('incremental', chunks.bytesize), chunks
  end

  def test_incremental_absorb_matches_one_shot
    xof = K::Xof.new(136)
    xof.absorb('a' * 100)
    xof.absorb('b' * 200)
    assert_equal K.shake256('a' * 100 + 'b' * 200, 64), xof.squeeze(64)
  end

  def test_absorb_after_squeeze_raises
    xof = K::Xof.new(168)
    xof.absorb('x')
    xof.squeeze(1)
    assert_raises(RuntimeError) { xof.absorb('y') }
  end

  # Differential testing against OpenSSL (skipped if unavailable).
  def test_differential_vs_openssl
    require 'openssl'
    begin
      OpenSSL::Digest.new('SHA3-256')
    rescue StandardError
      skip 'OpenSSL without SHA-3 support'
    end
    require 'securerandom'
    50.times do
      msg = SecureRandom.random_bytes(rand(0..400))
      assert_equal OpenSSL::Digest.new('SHA3-256').digest(msg), K.sha3_256(msg), "SHA3-256 len=#{msg.bytesize}"
      assert_equal OpenSSL::Digest.new('SHA3-512').digest(msg), K.sha3_512(msg), "SHA3-512 len=#{msg.bytesize}"
      assert_equal OpenSSL::Digest.new('SHAKE128').digest(msg), K.shake128(msg, 16), "SHAKE128 len=#{msg.bytesize}"
      assert_equal OpenSSL::Digest.new('SHAKE256').digest(msg), K.shake256(msg, 32), "SHAKE256 len=#{msg.bytesize}"
    end
  end
end
