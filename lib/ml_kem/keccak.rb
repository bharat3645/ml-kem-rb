# frozen_string_literal: true

module MLKem
  # Keccak-f[1600] and the FIPS 202 sponge functions needed by ML-KEM:
  # SHA3-256, SHA3-512, SHAKE128, SHAKE256 (with incremental squeezing).
  #
  # Pure Ruby, stdlib only. Round constants and rotation offsets are computed
  # from their FIPS 202 definitions at load time rather than hardcoded, so a
  # transcription mistake is impossible; correctness is established by the
  # differential test suite against OpenSSL's SHA3/SHAKE implementations.
  module Keccak
    MASK = (1 << 64) - 1

    # Rotation offsets (rho step), computed per FIPS 202 §3.2.2.
    RHO = begin
      r = Array.new(5) { Array.new(5, 0) }
      x, y = 1, 0
      (0..23).each do |t|
        r[x][y] = ((t + 1) * (t + 2) / 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
      end
      r
    end.freeze

    # Round constants (iota step), computed from the rc(t) LFSR, FIPS 202 §3.2.5.
    RC = begin
      # rc(t): LFSR over GF(2) with polynomial x^8+x^6+x^5+x^4+1 (0x171),
      # R initialized to 1, output is bit 0 (FIPS 202 Algorithm 5).
      rc_bit = lambda do |t|
        return 1 if t % 255 == 0
        r = 1
        (1..(t % 255)).each do
          r <<= 1
          r ^= 0x171 if (r & 0x100) != 0
        end
        r & 1
      end
      (0..23).map do |ir|
        rc = 0
        (0..6).each do |j|
          rc |= (rc_bit.call(j + 7 * ir) << ((1 << j) - 1))
        end
        rc
      end
    end.freeze

    # Precomputed rho+pi wiring: PI_DST[src] = destination index, ROT[src] =
    # left-rotation applied to lane +src+ on its way there. Derived from the
    # same FIPS 202 definitions as RHO above.
    PI_DST = begin
      dst = Array.new(25)
      (0..4).each do |x|
        (0..4).each do |y|
          dst[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5)
        end
      end
      dst
    end.freeze
    ROT = (0...25).map { |i| RHO[i % 5][i / 5] }.freeze

    module_function

    # One Keccak-f[1600] permutation over a 25-element array of 64-bit lanes
    # (index = x + 5*y). Mutates and returns +a+.
    def permute(a)
      b = Array.new(25)
      24.times do |round|
        # theta
        c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]
        c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]
        c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]
        c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]
        c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]
        d0 = c4 ^ (((c1 << 1) | (c1 >> 63)) & MASK)
        d1 = c0 ^ (((c2 << 1) | (c2 >> 63)) & MASK)
        d2 = c1 ^ (((c3 << 1) | (c3 >> 63)) & MASK)
        d3 = c2 ^ (((c4 << 1) | (c4 >> 63)) & MASK)
        d4 = c3 ^ (((c0 << 1) | (c0 >> 63)) & MASK)
        0.step(20, 5) do |i|
          a[i] ^= d0
          a[i + 1] ^= d1
          a[i + 2] ^= d2
          a[i + 3] ^= d3
          a[i + 4] ^= d4
        end

        # rho + pi (precomputed wiring)
        i = 0
        while i < 25
          v = a[i]
          off = ROT[i]
          v = (((v << off) | (v >> (64 - off))) & MASK) unless off.zero?
          b[PI_DST[i]] = v
          i += 1
        end

        # chi
        0.step(20, 5) do |j|
          b0 = b[j]; b1 = b[j + 1]; b2 = b[j + 2]; b3 = b[j + 3]; b4 = b[j + 4]
          a[j]     = b0 ^ ((~b1 & MASK) & b2)
          a[j + 1] = b1 ^ ((~b2 & MASK) & b3)
          a[j + 2] = b2 ^ ((~b3 & MASK) & b4)
          a[j + 3] = b3 ^ ((~b4 & MASK) & b0)
          a[j + 4] = b4 ^ ((~b0 & MASK) & b1)
        end

        # iota
        a[0] ^= RC[round]
      end
      a
    end

    # Sponge with byte-rate +rate+, domain-separation suffix +suffix+
    # (0x06 for SHA-3, 0x1F for SHAKE). One-shot squeeze of +out_len+ bytes.
    def sponge(rate, suffix, message, out_len)
      Xof.new(rate, suffix).absorb(message).squeeze(out_len)
    end

    def sha3_256(m) = sponge(136, 0x06, m, 32)
    def sha3_512(m) = sponge(72, 0x06, m, 64)
    def shake128(m, out_len) = sponge(168, 0x1F, m, out_len)
    def shake256(m, out_len) = sponge(136, 0x1F, m, out_len)

    # Incremental XOF: absorb any number of times, then squeeze any number of
    # times (absorbing after squeezing has begun is not allowed).
    class Xof
      def initialize(rate, suffix = 0x1F)
        @rate = rate
        @suffix = suffix
        @state = Array.new(25, 0)
        @buffer = +''
        @squeezing = false
        @squeeze_buf = +''
      end

      def absorb(bytes)
        raise 'cannot absorb after squeezing' if @squeezing

        @buffer << bytes.b
        while @buffer.bytesize >= @rate
          absorb_block(@buffer.byteslice(0, @rate))
          @buffer = @buffer.byteslice(@rate, @buffer.bytesize - @rate) || +''
        end
        self
      end

      def squeeze(n)
        unless @squeezing
          pad = @buffer.b + "\x00".b * (@rate - @buffer.bytesize)
          pad.setbyte(@buffer.bytesize, pad.getbyte(@buffer.bytesize) ^ @suffix)
          pad.setbyte(@rate - 1, pad.getbyte(@rate - 1) ^ 0x80)
          absorb_block(pad)
          @squeezing = true
          @squeeze_buf = squeeze_block
        end
        while @squeeze_buf.bytesize < n
          Keccak.permute(@state)
          @squeeze_buf << squeeze_block
        end
        out = @squeeze_buf.byteslice(0, n)
        @squeeze_buf = @squeeze_buf.byteslice(n, @squeeze_buf.bytesize - n) || +''
        out
      end

      private

      def absorb_block(block)
        lanes = block.unpack('Q<*')
        lanes.each_with_index { |lane, i| @state[i] ^= lane }
        # rate is always a multiple of 8 for our instances (168, 136, 72)
        Keccak.permute(@state)
      end

      def squeeze_block
        @state[0, @rate / 8].pack('Q<*')
      end
    end
  end
end
