# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/ml_kem'

class TestMLKem < Minitest::Test
  SIZES = {
    512  => { ek: 800,  dk: 1632, ct: 768 },
    768  => { ek: 1184, dk: 2400, ct: 1088 },
    1024 => { ek: 1568, dk: 3168, ct: 1568 },
  }.freeze

  def test_roundtrip_all_parameter_sets
    SIZES.each do |strength, sz|
      kem = MLKem::KEM.new(strength)
      ek, dk = kem.keygen
      assert_equal sz[:ek], ek.bytesize, "ek size #{strength}"
      assert_equal sz[:dk], dk.bytesize, "dk size #{strength}"
      key, ct = kem.encaps(ek)
      assert_equal sz[:ct], ct.bytesize, "ct size #{strength}"
      assert_equal 32, key.bytesize
      assert_equal key, kem.decaps(dk, ct), "roundtrip #{strength}"
    end
  end

  def test_unknown_parameter_set_rejected
    assert_raises(ArgumentError) { MLKem::KEM.new(999) }
  end

  def test_deterministic_keygen_reproducible
    kem = MLKem::KEM.new(768)
    d = "\x01" * 32
    z = "\x02" * 32
    assert_equal kem.keygen_derand(d, z), kem.keygen_derand(d, z)
    refute_equal kem.keygen_derand(d, z), kem.keygen_derand(z, d)
  end

  def test_implicit_rejection_on_tampered_ciphertext
    kem = MLKem::KEM.new(768)
    ek, dk = kem.keygen
    key, ct = kem.encaps(ek)
    bad = ct.dup
    bad.setbyte(5, bad.getbyte(5) ^ 0xFF)
    other = kem.decaps(dk, bad)
    assert_equal 32, other.bytesize
    refute_equal key, other
    # deterministic rejection: same bad ct → same derived key
    assert_equal other, kem.decaps(dk, bad)
  end

  def test_ek_length_validation
    kem = MLKem::KEM.new(768)
    assert_raises(MLKem::Error) { kem.encaps('short') }
  end

  def test_ek_modulus_check
    kem = MLKem::KEM.new(768)
    ek, = kem.keygen
    bad = ek.dup
    # Force the first 12-bit coefficient to 0xFFF (= 4095 ≥ q): fails modulus check.
    bad.setbyte(0, 0xFF)
    bad.setbyte(1, bad.getbyte(1) | 0x0F)
    assert_raises(MLKem::Error) { kem.encaps(bad) }
  end

  def test_dk_hash_check
    kem = MLKem::KEM.new(768)
    ek, dk = kem.keygen
    _, ct = kem.encaps(ek)
    bad = dk.dup
    bad.setbyte(384 * 3 + 10, bad.getbyte(384 * 3 + 10) ^ 1) # corrupt embedded ek
    assert_raises(MLKem::Error) { kem.decaps(bad, ct) }
  end

  def test_ct_length_validation
    kem = MLKem::KEM.new(768)
    _, dk = kem.keygen
    assert_raises(MLKem::Error) { kem.decaps(dk, 'x' * 10) }
  end

  def test_seed_length_validation
    kem = MLKem::KEM.new(768)
    assert_raises(MLKem::Error) { kem.keygen_derand('short', "\x00" * 32) }
    assert_raises(MLKem::Error) { kem.keygen_derand("\x00" * 32, 'short') }
    ek, = kem.keygen
    assert_raises(MLKem::Error) { kem.encaps_derand(ek, 'short') }
  end

  # C2SP/CCTV ML-KEM-768 intermediate-values vector (draft/ipd semantics:
  # (ρ,σ) = G(d) without the rank byte — the only KeyGen difference from the
  # final standard). Source: github.com/C2SP/CCTV, CC0.
  # The exact shared-secret match transitively pins down ek byte-for-byte
  # (K = G(m ‖ H(ek))[0,32]) and dk via the re-encrypt round in Decaps.
  def test_cctv_768_intermediate_vector_ipd
    kem = MLKem::KEM.new(768)
    kem.instance_variable_set(:@ipd_mode, true)
    d = ['f688563f7c66a5da2d8bdb5a5f3e07bd8dce6f7efcec7f41298d79863459f7cd'].pack('H*')
    z = ['d1d49a515250dbceb9f6e3fcc1c7d5306918964b21ddb22207e03e57f0600da8'].pack('H*')
    m = ['3dc27ca0a6594b0e56320457c45a0f76bb8a213ea4a76d442186a0aefadbcdb9'].pack('H*')

    ek, dk = kem.keygen_derand(d, z)
    assert_equal 'd0f1a257', ek.byteslice(0, 4).unpack1('H*')
    assert_equal '3261790e', dk.byteslice(0, 4).unpack1('H*')

    key, ct = kem.encaps_derand(ek, m)
    assert_equal '4b4eba37eff0315dc6009dcffb4dfbbb680f8f2ebde8715fa3d6daf70256a2d9', key.unpack1('H*')
    assert_equal key, kem.decaps(dk, ct)
  end

  # Final-FIPS-203 KATs from github.com/post-quantum-cryptography/KAT
  # (MLKEM/kat_MLKEM_{512,768,1024}.rsp). All three sets share the same
  # z/d/msg inputs for count=0; ss differs per set.
  KAT_Z = 'f696484048ec21f96cf50a56d0759c448f3779752f0383d37449690694cf7a68'
  KAT_D = '6dbbc4375136df3b07f7c70e639e223e177e7fd53b161b3f4d57791794f12624'
  KAT_M = '20a7b7e10f70496cc38220b944def699bf14d14e55cf4c90a12c1b33fc80ffff'
  KAT_SS = {
    512  => '2b5c52ee72946331983ba050be0f435055c0547901e03559b356517889ea27c5',
    768  => 'b408d5d115713f0a93047dbbea832e4340787686d59a9a2d106bd662ba0aa035',
    1024 => '23f211b84a6ee20c8c29f6e5314c91b414e940513d380add17bd724ab3a13a52',
  }.freeze

  def test_final_fips203_kat_vector0_all_sets
    KAT_SS.each do |strength, want_ss|
      kem = MLKem::KEM.new(strength)
      ek, dk = kem.keygen_derand([KAT_D].pack('H*'), [KAT_Z].pack('H*'))
      key, ct = kem.encaps_derand(ek, [KAT_M].pack('H*'))
      assert_equal want_ss, key.unpack1('H*'), "ML-KEM-#{strength} KAT ss"
      assert_equal key, kem.decaps(dk, ct), "ML-KEM-#{strength} KAT decaps"
    end
  end

  # ML-KEM-768 KAT counts 1–4 from the same file.
  KAT_768_MORE = [
    %w[6de62e3465a55c9c78a07d265be8540b3e58b0801a124d07ff12b438d5202ea0
       d69cfc64f84d4f33e4c54e166b7ff9283a394986a539b23987a10f39d2d9689b
       0121cb32acd1871135cb34e29c1a0e26ccc001b939eafaacc28f13f1938dbf91
       8c970242406111e26368ad8760c4d02a8b28d17d138210adc127197b50968140],
    %w[1eaae6bb91b27cd748c402c4111140d5a942cf3c95ff7977f88d2ef515bb26d0
       63470357110828f25b23edc80ed280ecd398a9f53251c3332754de2af0b15e90
       34b961af5d6254af72c0d50e70dd9b4991150ccc09192aa46f1953d5c29a33ec
       c0d45764e3dbf0948b914d6f65c92bd0ebd21556e5076753af48df8fffd6badc],
    %w[b585d4eb01085111a172a87688d0032e3381a9e9a35fdd6ef2f8aeb3b40eb5ce
       89b0c4b23019af3498a27da290892d981dd59fa08993bc05da21e1d72503664c
       0f4a070a0116194e267437545569d94aa5b2e4400645d5de88c504b9dbb1455e
       d71bd5a07c158c130283ef854516d290a46ade09a63831c7b83b8fd0724c8fb0],
  ].freeze

  def test_final_fips203_kat_768_counts_1_to_3
    kem = MLKem::KEM.new(768)
    KAT_768_MORE.each_with_index do |(z, d, m, ss), idx|
      ek, dk = kem.keygen_derand([d].pack('H*'), [z].pack('H*'))
      key, ct = kem.encaps_derand(ek, [m].pack('H*'))
      assert_equal ss, key.unpack1('H*'), "768 KAT count=#{idx + 1} ss"
      assert_equal key, kem.decaps(dk, ct)
    end
  end

  def test_final_mode_differs_from_ipd_only_in_keygen
    d = "\x11" * 32
    z = "\x22" * 32
    final = MLKem::KEM.new(768)
    ipd = MLKem::KEM.new(768)
    ipd.instance_variable_set(:@ipd_mode, true)
    ek_f, = final.keygen_derand(d, z)
    ek_i, = ipd.keygen_derand(d, z)
    refute_equal ek_f, ek_i, 'final adds the rank byte to G(d)'
    # Encaps/Decaps are identical algorithms: a final-mode KEM interoperates
    # with ipd-mode keys (content differs, mechanics don't).
    key, ct = final.encaps(ek_i)
    _, dk_i = ipd.keygen_derand(d, z)
    assert_equal key, final.decaps(dk_i, ct)
  end
end
