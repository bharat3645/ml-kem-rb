# frozen_string_literal: true

require 'securerandom'
require_relative 'ml_kem/keccak'
require_relative 'ml_kem/version'

# Pure-Ruby ML-KEM (FIPS 203): ML-KEM-512 / -768 / -1024.
#
# KAT-verified reference implementation. NOT side-channel hardened — see the
# README's security section before using in production.
module MLKem
  N = 256
  Q = 3329

  PARAMS = {
    512  => { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4 }.freeze,
    768  => { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4 }.freeze,
    1024 => { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5 }.freeze,
  }.freeze

  # 17^BitRev7(i) mod q — computed, not transcribed (17 is the canonical
  # primitive 256th root of unity mod 3329, FIPS 203 §4.3).
  BITREV7 = (0...128).map { |i| (0...7).sum { |b| ((i >> b) & 1) << (6 - b) } }.freeze
  ZETAS = BITREV7.map { |e| 17.pow(e, Q) }.freeze
  # gamma_i = 17^(2*BitRev7(i)+1), used by MultiplyNTTs (FIPS 203 §4.3.1).
  GAMMAS = BITREV7.map { |e| 17.pow(2 * e + 1, Q) }.freeze
  INV_128 = 3303 # 128^-1 mod 3329

  class Error < StandardError; end

  # One parameter set (512/768/1024) of the ML-KEM key-encapsulation mechanism.
  class KEM
    attr_reader :strength, :k, :ek_size, :dk_size, :ct_size

    def initialize(strength = 768)
      p = PARAMS[strength] or raise ArgumentError, "unknown parameter set #{strength.inspect} (use 512, 768, or 1024)"
      @strength = strength
      @k = p[:k]
      @eta1 = p[:eta1]
      @eta2 = p[:eta2]
      @du = p[:du]
      @dv = p[:dv]
      @ek_size = 384 * @k + 32
      @dk_size = 768 * @k + 96
      @ct_size = 32 * (@du * @k + @dv)
      # ipd_mode reproduces the FIPS 203 *draft* KeyGen (G(d) without the rank
      # byte) — exists only so the test suite can run the CCTV/pq-crystals
      # draft-era vectors. Never use it outside tests.
      @ipd_mode = false
    end

    # --- public API -------------------------------------------------------

    # => [ek, dk] (encapsulation key, decapsulation key), random.
    def keygen
      keygen_derand(SecureRandom.random_bytes(32), SecureRandom.random_bytes(32))
    end

    # Deterministic ML-KEM.KeyGen_internal(d, z) — for KATs and reproducibility.
    def keygen_derand(d, z)
      raise Error, 'd must be 32 bytes' unless d.bytesize == 32
      raise Error, 'z must be 32 bytes' unless z.bytesize == 32

      ek, dk_pke = kpke_keygen(d)
      dk = dk_pke + ek + h(ek) + z
      [ek, dk]
    end

    # => [K, ct] (32-byte shared secret, ciphertext), random.
    def encaps(ek)
      encaps_derand(ek, SecureRandom.random_bytes(32))
    end

    # Deterministic ML-KEM.Encaps_internal(ek, m) — for KATs.
    def encaps_derand(ek, m)
      raise Error, 'm must be 32 bytes' unless m.bytesize == 32

      validate_ek!(ek)
      key_r = g(m + h(ek))
      key = key_r.byteslice(0, 32)
      r = key_r.byteslice(32, 32)
      ct = kpke_encrypt(ek, m, r)
      [key, ct]
    end

    # ML-KEM.Decaps(dk, ct) => 32-byte shared secret (implicit rejection on
    # invalid ciphertexts, per FIPS 203 — never raises for a wrong ct).
    def decaps(dk, ct)
      validate_dk!(dk)
      raise Error, "ciphertext must be #{@ct_size} bytes" unless ct.bytesize == @ct_size

      dk_pke = dk.byteslice(0, 384 * @k)
      ek = dk.byteslice(384 * @k, @ek_size)
      hek = dk.byteslice(384 * @k + @ek_size, 32)
      z = dk.byteslice(384 * @k + @ek_size + 32, 32)

      m2 = kpke_decrypt(dk_pke, ct)
      key_r = g(m2 + hek)
      key2 = key_r.byteslice(0, 32)
      r2 = key_r.byteslice(32, 32)
      key_bar = j(z + ct)
      ct2 = kpke_encrypt(ek, m2, r2)
      constant_time_eq(ct, ct2) ? key2 : key_bar
    end

    # --- FIPS 203 input validation ---------------------------------------

    # Encapsulation-key check: length + modulus (re-encode round-trip).
    def validate_ek!(ek)
      raise Error, "ek must be #{@ek_size} bytes" unless ek.bytesize == @ek_size

      (0...@k).each do |i|
        chunk = ek.byteslice(384 * i, 384)
        raise Error, 'ek coefficients not reduced mod q (modulus check failed)' unless byte_encode(byte_decode(chunk, 12), 12) == chunk
      end
      true
    end

    # Decapsulation-key check: length + hash consistency of the embedded ek.
    def validate_dk!(dk)
      raise Error, "dk must be #{@dk_size} bytes" unless dk.bytesize == @dk_size

      ek = dk.byteslice(384 * @k, @ek_size)
      hek = dk.byteslice(384 * @k + @ek_size, 32)
      raise Error, 'dk hash check failed (corrupted decapsulation key)' unless h(ek) == hek
      true
    end

    private

    # --- hash / XOF wrappers (FIPS 203 §4.1) ------------------------------

    def h(m) = Keccak.sha3_256(m)
    def g(m) = Keccak.sha3_512(m)
    def j(m) = Keccak.shake256(m, 32)
    def prf(eta, s, b) = Keccak.shake256(s + b.chr, 64 * eta)

    # --- K-PKE (FIPS 203 §5) ----------------------------------------------

    def kpke_keygen(d)
      seed = @ipd_mode ? d : d + @k.chr
      rho_sigma = g(seed)
      rho = rho_sigma.byteslice(0, 32)
      sigma = rho_sigma.byteslice(32, 32)

      a_hat = matrix_a(rho)
      n_ctr = 0
      s = Array.new(@k) { |_| p = cbd(@eta1, prf(@eta1, sigma, n_ctr)); n_ctr += 1; p }
      e = Array.new(@k) { |_| p = cbd(@eta1, prf(@eta1, sigma, n_ctr)); n_ctr += 1; p }
      s_hat = s.map { |p| ntt(p) }
      e_hat = e.map { |p| ntt(p) }

      t_hat = (0...@k).map do |i|
        acc = Array.new(N, 0)
        (0...@k).each { |jj| acc = poly_add(acc, multiply_ntts(a_hat[i][jj], s_hat[jj])) }
        poly_add(acc, e_hat[i])
      end

      ek = t_hat.map { |p| byte_encode(p, 12) }.join + rho
      dk = s_hat.map { |p| byte_encode(p, 12) }.join
      [ek, dk]
    end

    def kpke_encrypt(ek, m, r)
      t_hat = (0...@k).map { |i| byte_decode(ek.byteslice(384 * i, 384), 12) }
      rho = ek.byteslice(384 * @k, 32)
      a_hat = matrix_a(rho)

      n_ctr = 0
      y = Array.new(@k) { |_| p = cbd(@eta1, prf(@eta1, r, n_ctr)); n_ctr += 1; p }
      e1 = Array.new(@k) { |_| p = cbd(@eta2, prf(@eta2, r, n_ctr)); n_ctr += 1; p }
      e2 = cbd(@eta2, prf(@eta2, r, n_ctr))

      y_hat = y.map { |p| ntt(p) }

      u = (0...@k).map do |i|
        acc = Array.new(N, 0)
        # A^T: A[j][i]
        (0...@k).each { |jj| acc = poly_add(acc, multiply_ntts(a_hat[jj][i], y_hat[jj])) }
        poly_add(inv_ntt(acc), e1[i])
      end

      mu = decompress(byte_decode(m, 1), 1)
      acc = Array.new(N, 0)
      (0...@k).each { |i| acc = poly_add(acc, multiply_ntts(t_hat[i], y_hat[i])) }
      v = poly_add(poly_add(inv_ntt(acc), e2), mu)

      c1 = u.map { |p| byte_encode(compress(p, @du), @du) }.join
      c2 = byte_encode(compress(v, @dv), @dv)
      c1 + c2
    end

    def kpke_decrypt(dk_pke, ct)
      u = (0...@k).map do |i|
        decompress(byte_decode(ct.byteslice(32 * @du * i, 32 * @du), @du), @du)
      end
      v = decompress(byte_decode(ct.byteslice(32 * @du * @k, 32 * @dv), @dv), @dv)
      s_hat = (0...@k).map { |i| byte_decode(dk_pke.byteslice(384 * i, 384), 12) }

      acc = Array.new(N, 0)
      (0...@k).each { |i| acc = poly_add(acc, multiply_ntts(s_hat[i], ntt(u[i]))) }
      w = poly_sub(v, inv_ntt(acc))
      byte_encode(compress(w, 1), 1)
    end

    # Â[i][j] ← SampleNTT(XOF(ρ ‖ j ‖ i)) — FIPS 203 final / Kyber round 3
    # convention (row i, column j; XOF input is column-then-row).
    def matrix_a(rho)
      Array.new(@k) do |i|
        Array.new(@k) do |jj|
          sample_ntt(rho, jj, i)
        end
      end
    end

    # --- sampling (FIPS 203 §4.2.2) ---------------------------------------

    def sample_ntt(rho, b1, b2)
      xof = Keccak::Xof.new(168)
      xof.absorb(rho + b1.chr + b2.chr)
      coeffs = []
      buf = xof.squeeze(504) # 3 SHAKE128 blocks; typically enough (>2^-38 not)
      pos = 0
      while coeffs.size < N
        if pos + 3 > buf.bytesize
          buf = xof.squeeze(168)
          pos = 0
        end
        b0 = buf.getbyte(pos)
        bb1 = buf.getbyte(pos + 1)
        bb2 = buf.getbyte(pos + 2)
        pos += 3
        d1 = b0 + 256 * (bb1 & 0xF)
        d2 = (bb1 >> 4) + 16 * bb2
        coeffs << d1 if d1 < Q
        coeffs << d2 if d2 < Q && coeffs.size < N
      end
      coeffs
    end

    def cbd(eta, bytes)
      bits = []
      bytes.each_byte do |byte|
        8.times { |b| bits << ((byte >> b) & 1) }
      end
      Array.new(N) do |i|
        x = 0
        y = 0
        eta.times do |jj|
          x += bits[2 * i * eta + jj]
          y += bits[2 * i * eta + eta + jj]
        end
        (x - y) % Q
      end
    end

    # --- NTT (FIPS 203 §4.3) ----------------------------------------------

    def ntt(f)
      f = f.dup
      i = 1
      len = 128
      while len >= 2
        start = 0
        while start < N
          zeta = ZETAS[i]
          i += 1
          (start...(start + len)).each do |jj|
            t = (zeta * f[jj + len]) % Q
            f[jj + len] = (f[jj] - t) % Q
            f[jj] = (f[jj] + t) % Q
          end
          start += 2 * len
        end
        len >>= 1
      end
      f
    end

    def inv_ntt(f)
      f = f.dup
      i = 127
      len = 2
      while len <= 128
        start = 0
        while start < N
          zeta = ZETAS[i]
          i -= 1
          (start...(start + len)).each do |jj|
            t = f[jj]
            f[jj] = (t + f[jj + len]) % Q
            f[jj + len] = (zeta * (f[jj + len] - t)) % Q
          end
          start += 2 * len
        end
        len <<= 1
      end
      f.map { |x| (x * INV_128) % Q }
    end

    def multiply_ntts(f, g_)
      h_ = Array.new(N)
      (0...128).each do |i|
        a0 = f[2 * i]
        a1 = f[2 * i + 1]
        b0 = g_[2 * i]
        b1 = g_[2 * i + 1]
        h_[2 * i] = (a0 * b0 + a1 * b1 % Q * GAMMAS[i]) % Q
        h_[2 * i + 1] = (a0 * b1 + a1 * b0) % Q
      end
      h_
    end

    def poly_add(a, b) = a.map.with_index { |x, i| (x + b[i]) % Q }
    def poly_sub(a, b) = a.map.with_index { |x, i| (x - b[i]) % Q }

    # --- compression & byte encoding (FIPS 203 §4.2.1) ---------------------

    def compress(poly, d)
      poly.map { |x| (((x << d) * 2 + Q) / (2 * Q)) & ((1 << d) - 1) }
    end

    def decompress(poly, d)
      poly.map { |y| (y * Q + (1 << (d - 1))) >> d }
    end

    def byte_encode(poly, d)
      out = "\x00".b * (32 * d)
      acc = 0
      acc_bits = 0
      pos = 0
      poly.each do |c|
        acc |= c << acc_bits
        acc_bits += d
        while acc_bits >= 8
          out.setbyte(pos, acc & 0xFF)
          pos += 1
          acc >>= 8
          acc_bits -= 8
        end
      end
      out
    end

    def byte_decode(bytes, d)
      mask = (1 << d) - 1
      out = Array.new(N)
      acc = 0
      acc_bits = 0
      pos = 0
      idx = 0
      while idx < N
        while acc_bits < d
          acc |= bytes.getbyte(pos) << acc_bits
          pos += 1
          acc_bits += 8
        end
        v = acc & mask
        acc >>= d
        acc_bits -= d
        out[idx] = d == 12 ? v % Q : v
        idx += 1
      end
      out
    end

    def constant_time_eq(a, b)
      return false unless a.bytesize == b.bytesize

      diff = 0
      a.bytes.each_with_index { |byte, i| diff |= byte ^ b.getbyte(i) }
      diff.zero?
    end
  end
end
