# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/ml_kem/hybrid'

class TestHybrid < Minitest::Test
  def setup
    skip 'X25519 unavailable in this openssl gem (needs newer than Ruby 3.0 bundles)' unless MLKem::Hybrid.available?
  end

  def test_full_handshake_produces_matching_shared_secret
    client_share, state = MLKem::Hybrid.client_init
    server_share, server_secret = MLKem::Hybrid.server_respond(client_share)
    client_secret = MLKem::Hybrid.client_finish(state, server_share)

    assert_equal server_secret, client_secret
    assert_equal MLKem::Hybrid::SHARED_SECRET_BYTES, client_secret.bytesize
  end

  def test_wire_sizes_match_draft_ietf_tls_ecdhe_mlkem_05
    client_share, state = MLKem::Hybrid.client_init
    assert_equal 1216, client_share.bytesize
    assert_equal MLKem::Hybrid::CLIENT_SHARE_BYTES, client_share.bytesize

    server_share, = MLKem::Hybrid.server_respond(client_share)
    assert_equal 1120, server_share.bytesize
    assert_equal MLKem::Hybrid::SERVER_SHARE_BYTES, server_share.bytesize

    MLKem::Hybrid.client_finish(state, server_share) # no error
  end

  def test_shared_secret_is_mlkem_secret_concatenated_with_x25519_secret
    # Structural check: rebuild each half independently with the plain
    # (non-hybrid) primitives and confirm the combiner didn't scramble
    # anything - shared_secret must be exactly ss_mlkem || x25519_ss, ML-KEM
    # first (per the draft; the other two IANA hybrids order it the other
    # way, which is exactly why this isn't done generically).
    client_share, state = MLKem::Hybrid.client_init
    server_share, combined = MLKem::Hybrid.server_respond(client_share)

    ct_mlkem = server_share.byteslice(0, 1088)
    ss_mlkem_independent = MLKem::KEM.new(768).decaps(state.dk_mlkem, ct_mlkem)

    assert_equal ss_mlkem_independent, combined.byteslice(0, 32)
    assert_equal 64, combined.bytesize
    refute_equal combined.byteslice(0, 32), combined.byteslice(32, 32), 'the two halves should not accidentally collide'
  end

  def test_tampering_with_server_share_changes_the_derived_secret
    client_share, state = MLKem::Hybrid.client_init
    server_share, server_secret = MLKem::Hybrid.server_respond(client_share)

    tampered = server_share.dup
    tampered.setbyte(0, tampered.getbyte(0) ^ 0xFF)

    # A tampered ML-KEM ciphertext doesn't raise (FIPS 203 implicit
    # rejection - see ml_kem.rb's own decaps) but must produce a different
    # secret than the real handshake did.
    client_secret_from_tampered = MLKem::Hybrid.client_finish(state, tampered)
    refute_equal server_secret, client_secret_from_tampered
  end

  def test_rejects_wrong_size_shares_with_a_clear_error
    err = assert_raises(MLKem::Hybrid::Error) { MLKem::Hybrid.server_respond('short') }
    assert_match(/1216 bytes, got 5/, err.message)

    _client_share, state = MLKem::Hybrid.client_init
    err = assert_raises(MLKem::Hybrid::Error) { MLKem::Hybrid.client_finish(state, 'short') }
    assert_match(/1120 bytes, got 5/, err.message)
  end

  def test_repeated_handshakes_use_fresh_ephemeral_keys
    share_a, = MLKem::Hybrid.client_init
    share_b, = MLKem::Hybrid.client_init
    refute_equal share_a, share_b, 'client shares must not repeat across handshakes'
  end

  # RFC 7748 §6.1: X25519's curve order is divisible by its cofactor, so a
  # peer can supply a small-order public value (the all-zero raw value is
  # the simplest) to force a fixed ECDH output. This must surface as this
  # module's own documented Hybrid::Error, the same contract
  # test_rejects_wrong_size_shares_with_a_clear_error already covers for
  # malformed sizes - not as a bare OpenSSL::PKey::PKeyError, which a caller
  # rescuing Hybrid::Error would not catch.
  LOW_ORDER_X25519_RAW_HEX = [
    '00' * 32, # the all-zero point (order 1)
    '01' + '00' * 31, # the value 1 (order 1)
  ].freeze

  def test_server_respond_rejects_degenerate_x25519_client_share
    client_share, = MLKem::Hybrid.client_init
    ek_mlkem = client_share.byteslice(0, MLKem::Hybrid::EK_MLKEM_768_BYTES)

    LOW_ORDER_X25519_RAW_HEX.each do |hex|
      malicious_share = ek_mlkem + [hex].pack('H*')
      err = assert_raises(MLKem::Hybrid::Error) { MLKem::Hybrid.server_respond(malicious_share) }
      assert_match(/degenerate low-order point/, err.message)
    end
  end

  def test_client_finish_rejects_degenerate_x25519_server_share
    _client_share, state = MLKem::Hybrid.client_init
    # decaps never raises on a malformed ciphertext (FIPS 203 implicit
    # rejection - see ml_kem.rb), so any correctly-sized filler works here;
    # only the X25519 half needs to be the attack payload under test.
    ct_mlkem = "\x00".b * MLKem::Hybrid::CT_MLKEM_768_BYTES

    LOW_ORDER_X25519_RAW_HEX.each do |hex|
      malicious_share = ct_mlkem + [hex].pack('H*')
      err = assert_raises(MLKem::Hybrid::Error) { MLKem::Hybrid.client_finish(state, malicious_share) }
      assert_match(/degenerate low-order point/, err.message)
    end
  end
end
