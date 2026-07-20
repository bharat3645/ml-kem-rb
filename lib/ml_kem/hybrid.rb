# frozen_string_literal: true

require 'openssl'
require_relative '../ml_kem'

module MLKem
  # X25519MLKEM768: the hybrid TLS 1.3 key-exchange group that Chrome and
  # Cloudflare deployed in 2024-25 and that IETF standardized as
  # draft-ietf-tls-ecdhe-mlkem-05 — the real-world transition pattern today
  # (hybrid classical+PQC, not a pure-PQC cutover). Byte layout verified
  # directly against that draft's normative text, not recalled from memory:
  #
  #   client share  = ek_mlkem (1184B) || x25519_client_pub (32B)   = 1216B
  #   server share  = ct_mlkem (1088B) || x25519_server_pub (32B)   = 1120B
  #   shared secret = ss_mlkem (32B)   || x25519_shared_secret(32B) =   64B
  #
  # (ML-KEM's secret is first in X25519MLKEM768 specifically - the other two
  # IANA-registered hybrids, SecP256r1MLKEM768 and SecP384r1MLKEM1024, put
  # the ECDH secret first instead. This module implements only the X25519
  # variant.)
  #
  # X25519 itself comes from the `openssl` stdlib gem, not a hand-rolled
  # implementation — Curve25519 arithmetic is exactly the kind of thing this
  # project's README already says it isn't trying to make side-channel-safe
  # for (see the ML-KEM implementation's own "not constant-time,
  # reference-quality" framing); reusing a vetted implementation here is the
  # correct engineering call, not corner-cutting.
  #
  # X25519 PKey support needs the openssl gem's raw-key-pair API, which
  # Ruby's *bundled* openssl gem did not ship until well after this
  # project's Ruby >= 3.0 floor (Ruby 3.0's bundled openssl 2.2.2 has no
  # X25519 PKey type at all: `OpenSSL::PKey.generate_key` itself is
  # undefined). Call `Hybrid.available?` before use; every method below
  # raises a clear `Hybrid::Unavailable` rather than a cryptic NoMethodError
  # if the running openssl gem can't do X25519.
  module Hybrid
    class Error < StandardError; end
    class Unavailable < Error; end

    # SubjectPublicKeyInfo DER prefix for an X25519 public key (RFC 8410):
    # SEQUENCE { SEQUENCE { OID id-X25519 } BIT STRING (33 bytes: 0x00 tag +
    # 32-byte key) }. Fixed and universal for every X25519 key — used to
    # reconstruct a PKey from a bare 32-byte wire value without needing the
    # newer `OpenSSL::PKey.new_raw_public_key` convenience method, which (like
    # `#raw_public_key`) only landed in openssl gem versions newer than this
    # project's floor. Verified against real `OpenSSL::PKey#public_to_der`
    # output before being hardcoded here.
    X25519_SPKI_PREFIX = ['302a300506032b656e032100'].pack('H*').freeze

    EK_MLKEM_768_BYTES = 1184
    X25519_BYTES = 32
    CLIENT_SHARE_BYTES = EK_MLKEM_768_BYTES + X25519_BYTES # 1216
    CT_MLKEM_768_BYTES = 1088
    SERVER_SHARE_BYTES = CT_MLKEM_768_BYTES + X25519_BYTES # 1120
    SHARED_SECRET_BYTES = 64

    MLKEM = MLKem::KEM.new(768)
    private_constant :MLKEM

    # Whether the running openssl gem can generate/derive X25519 keys at
    # all. Cheap: generating a real ephemeral key is the only reliable probe
    # (method existence alone doesn't guarantee the underlying OpenSSL
    # library was built with X25519 support).
    def self.available?
      return false unless OpenSSL::PKey.respond_to?(:generate_key)

      OpenSSL::PKey.generate_key('X25519')
      true
    rescue StandardError
      false
    end

    def self.ensure_available!
      return if available?

      raise Unavailable, 'X25519 support unavailable in this openssl gem ' \
                          '(needs a newer openssl gem than Ruby 3.0 bundles; ' \
                          'run `ruby -ropenssl -e "OpenSSL::PKey.generate_key(\'X25519\')"` to check)'
    end

    def self.raw_public_key(pkey)
      pkey.public_to_der[-X25519_BYTES..]
    end
    private_class_method :raw_public_key

    def self.pkey_from_raw_public_key(raw)
      raise Error, "X25519 public value must be #{X25519_BYTES} bytes, got #{raw.bytesize}" unless raw.bytesize == X25519_BYTES

      OpenSSL::PKey.read(X25519_SPKI_PREFIX + raw)
    end
    private_class_method :pkey_from_raw_public_key

    # Client state carried between client_init and client_finish. Opaque to
    # callers; only client_finish should read it.
    ClientState = Struct.new(:dk_mlkem, :x25519_key)

    # Client, step 1: generate both ephemeral keypairs.
    # => [client_share (1216 bytes, send to server), ClientState]
    def self.client_init
      ensure_available!
      ek, dk = MLKEM.keygen
      x25519_key = OpenSSL::PKey.generate_key('X25519')
      client_share = ek + raw_public_key(x25519_key)
      [client_share, ClientState.new(dk, x25519_key)]
    end

    # Server: given the client's share, encapsulate against the ML-KEM key,
    # generate an ephemeral X25519 keypair, and derive the combined secret.
    # => [server_share (1120 bytes, send to client), shared_secret (64 bytes)]
    def self.server_respond(client_share)
      ensure_available!
      unless client_share.bytesize == CLIENT_SHARE_BYTES
        raise Error, "client share must be #{CLIENT_SHARE_BYTES} bytes, got #{client_share.bytesize}"
      end

      ek_mlkem = client_share.byteslice(0, EK_MLKEM_768_BYTES)
      client_x25519_raw = client_share.byteslice(EK_MLKEM_768_BYTES, X25519_BYTES)

      ss_mlkem, ct_mlkem = MLKEM.encaps(ek_mlkem)

      server_x25519_key = OpenSSL::PKey.generate_key('X25519')
      client_x25519_pkey = pkey_from_raw_public_key(client_x25519_raw)
      x25519_shared = server_x25519_key.derive(client_x25519_pkey)

      server_share = ct_mlkem + raw_public_key(server_x25519_key)
      [server_share, ss_mlkem + x25519_shared]
    end

    # Client, step 2: given the server's share and the state from
    # client_init, recover the same combined secret.
    # => shared_secret (64 bytes)
    def self.client_finish(state, server_share)
      ensure_available!
      unless server_share.bytesize == SERVER_SHARE_BYTES
        raise Error, "server share must be #{SERVER_SHARE_BYTES} bytes, got #{server_share.bytesize}"
      end

      ct_mlkem = server_share.byteslice(0, CT_MLKEM_768_BYTES)
      server_x25519_raw = server_share.byteslice(CT_MLKEM_768_BYTES, X25519_BYTES)

      ss_mlkem = MLKEM.decaps(state.dk_mlkem, ct_mlkem)

      server_x25519_pkey = pkey_from_raw_public_key(server_x25519_raw)
      x25519_shared = state.x25519_key.derive(server_x25519_pkey)

      ss_mlkem + x25519_shared
    end
  end
end
