# frozen_string_literal: true

require 'openssl'
require 'English'
require 'securerandom'
require_relative '../protocol'

module PWN
  module Plugins
    module YubiKey
      module SecurityDomain
        # GlobalPlatform SCP03 (S8/AES128) and SCP11 session primitives.
        # Protocol reference: GP Card Specification 2.3 Amendments D/F;
        # interoperability reference: Yubico yubikit 5.9.1 core/smartcard/scp.py.
        # Independently implemented Ruby; no executable or Python backend.
        module SCP
          class ChannelError < YubiKey::ResponseError
          end

          # Native AES-CMAC, EC encoding and offline X509 verification.
          class Crypto
            def ec_key(value, private_key: false)
              key = value.is_a?(OpenSSL::PKey::EC) ? value : OpenSSL::PKey.read(value, '')
              raise ArgumentError, 'An EC key of the required kind is needed' unless key.is_a?(OpenSSL::PKey::EC) && (!private_key || key.private?) && key.check_key

              key
            rescue OpenSSL::OpenSSLError, TypeError
              raise ArgumentError, 'Invalid EC key encoding', cause: nil
            end

            def public_point(point, curve)
              group = OpenSSL::PKey::EC::Group.new(curve)
              raise ChannelError, 'Invalid uncompressed EC point' unless point.is_a?(String) && point.getbyte(0) == 4 && point.bytesize == 1 + (2 * ((group.degree + 7) / 8))

              algorithm = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'), OpenSSL::ASN1::ObjectId.new(curve)])
              ec_key(OpenSSL::ASN1::Sequence.new([algorithm, OpenSSL::ASN1::BitString.new(point)]).to_der)
            rescue OpenSSL::OpenSSLError, ArgumentError
              raise ChannelError, 'Invalid peer EC point', cause: nil
            end

            def certificates(values)
              raise ArgumentError, 'Certificates must be a nonempty bounded Array' unless values.is_a?(Array) && values.length.between?(1, 32)

              values.map do |value|
                cert = OpenSSL::X509::Certificate.new(value.is_a?(OpenSSL::X509::Certificate) ? value.to_der : value)
                raise ArgumentError, 'Certificate is too large' if cert.to_der.bytesize > 65_000

                cert
              end
            rescue OpenSSL::OpenSSLError, TypeError
              raise ArgumentError, 'Invalid X509 certificate encoding', cause: nil
            end

            def validate_chain(chain, roots = nil)
              now = Time.now
              raise ChannelError, 'Certificate validity check failed' if chain.any? { |cert| now < cert.not_before || now > cert.not_after }

              chain.each_cons(2) do |parent, child|
                ca = parent.extensions.find { |ext| ext.oid == 'basicConstraints' }
                usage = parent.extensions.find { |ext| ext.oid == 'keyUsage' }
                valid = child.issuer == parent.subject && child.verify(parent.public_key) && ca&.value&.include?('CA:TRUE') && (!usage || usage.value.include?('Certificate Sign'))
                raise ChannelError, 'Certificate chain verification failed' unless valid
              end
              if roots
                store = OpenSSL::X509::Store.new
                roots.each { |root| store.add_cert(root) }
                raise ChannelError, 'Untrusted card certificate chain' unless store.verify(chain.last, chain[0...-1])
              end
              usage = chain.last.extensions.find { |ext| ext.oid == 'keyUsage' }
              raise ChannelError, 'SCP11 leaf certificate requires keyAgreement usage' unless usage&.value&.include?('Key Agreement')

              ec_key(chain.last.public_key)
            rescue OpenSSL::OpenSSLError
              raise ChannelError, 'Certificate verification failed', cause: nil
            end

            def derive(key, type, context, bits = 128)
              cmac(key, ("\0".b * 11) + [type, 0, bits, 1].pack('CCnC') + context).byteslice(0, bits / 8)
            end

            def equal?(left, right)
              left.bytesize == right.bytesize && OpenSSL.fixed_length_secure_compare(left, right)
            end

            def cipher_iv(key, counter, response: false)
              aes(key, [response ? 0x80 : 0].pack('C') + [counter.to_s(16).rjust(30, '0')].pack('H*'))
            end

            def pad(data)
              (data + "\x80".b).ljust(((data.bytesize / 16) + 1) * 16, "\0".b)
            end

            def unpad(data)
              value = data.sub(/\x00*\z/n, ''.b)
              raise ChannelError, 'Invalid secure response padding' unless value.end_with?("\x80".b) && data.bytesize - value.bytesize < 16

              value.byteslice(0, value.bytesize - 1)
            end

            def aes(key, data, initialization_vector: nil, decrypt: false)
              cipher = OpenSSL::Cipher.new("aes-#{key.bytesize * 8}-#{initialization_vector ? 'cbc' : 'ecb'}")
              decrypt ? cipher.decrypt : cipher.encrypt
              cipher.padding = 0
              cipher.key = key
              cipher.iv = initialization_vector if initialization_vector
              (data.empty? ? ''.b : cipher.update(data)) + cipher.final
            end

            def xor(left, right)
              left.bytes.zip(right.bytes).map { |a, b| a ^ b }.pack('C*')
            end

            def double(block)
              value = block.unpack1('H*').to_i(16)
              value = ((value << 1) & ((1 << 128) - 1)) ^ (value[127] == 1 ? 0x87 : 0)
              [value.to_s(16).rjust(32, '0')].pack('H*')
            end

            def cmac(key, data)
              first = double(aes(key, "\0".b * 16))
              complete = !data.empty? && (data.bytesize % 16).zero?
              count = [1, (data.bytesize + 15) / 16].max
              last = data.byteslice((count - 1) * 16, 16) || ''.b
              last = complete ? xor(last, first) : xor((last + "\x80".b).ljust(16, "\0".b), double(first))
              chain = "\0".b * 16
              (count - 1).times { |index| chain = aes(key, xor(chain, data.byteslice(index * 16, 16))) }
              aes(key, xor(chain, last))
            end
          end

          # The connection owns the MAC chain, encryption counter and lifecycle.
          class Connection # rubocop:disable Metrics/ClassLength
            attr_reader :scp

            def initialize(opts)
              raise YubiKey::ConfirmationRequired, 'Secure-channel authentication requires confirm: true' unless opts[:confirm] == true

              @connection = opts.fetch(:connection)
              raise ArgumentError, 'Expected a plain APDU connection' unless @connection.descriptor[:protocol] == :apdu && !@connection.is_a?(Connection)

              @scp = opts.fetch(:scp)
              raise ArgumentError, 'Unsupported secure-channel protocol' unless %i[scp03 scp11a scp11b scp11c].include?(@scp)

              expected_kid = { scp03: 1, scp11a: 0x11, scp11b: 0x13, scp11c: 0x15 }.fetch(@scp)
              raise ArgumentError, 'KID does not match selected SCP variant' if opts.key?(:kid) && byte(opts[:kid]) != expected_kid

              @kvn = byte(opts.fetch(:kvn))
              @timeout = timeout(opts.fetch(:timeout, 30))
              @crypto = Crypto.new
              @mutex = Mutex.new
              @enc_counter = 1
              @chain = "\0".b * 16
              if @scp == :scp03
                keys = %i[key_enc key_mac].map { |name| aes_key(opts.fetch(name)) }
                @dek = aes_key(opts[:key_dek]) if opts[:key_dek]
              else
                prepare_scp11(opts)
              end
              @auth_deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + @timeout
              begin
                plain([0, 0xa4, 4, 0], ['a000000151000000'].pack('H*'))
                @scp == :scp03 ? initialize_scp03(keys) : initialize_scp11
                @ready = true
              ensure
                @oce_key = nil
                invalidate unless @ready
              end
            end

            def inspect
              "#<#{self.class} #{@scp} redacted>"
            end

            def descriptor
              @connection.descriptor.merge(secure_channel: @scp, extended_apdu: true, authenticated: @ready == true && !@closed && %i[scp03 scp11a].include?(@scp))
            end

            def authenticated?
              @ready == true && !@closed && %i[scp03 scp11a].include?(@scp)
            end

            def close
              @mutex.synchronize { invalidate }
              :closed
            end

            def exchange(opts = {})
              raise ArgumentError, 'Secure channel accepts only APDUs' unless opts[:protocol] == :apdu

              header, data, le, extended = decode(opts[:data])
              seconds = timeout(opts.fetch(:timeout, @timeout))
              @mutex.synchronize do
                raise ChannelError, 'Secure channel is closed' if @closed || !@ready

                complete = false
                begin
                  raise ChannelError, 'Secure-channel counter exhausted' if @enc_counter > 0xffffffff

                  counter = @enc_counter
                  encrypted = @crypto.aes(@enc, @crypto.pad(data), initialization_vector: @crypto.cipher_iv(@enc, counter))
                  @enc_counter += 1
                  header[0] |= 4
                  frame = encode(header, encrypted + ("\0".b * 8), nil, extended: extended)
                  @chain = @crypto.cmac(@mac, @chain + frame.byteslice(0, frame.bytesize - 8))
                  command = encode(header, encrypted + @chain.byteslice(0, 8), le, extended: extended)
                  response = transmit(command, Process.clock_gettime(Process::CLOCK_MONOTONIC) + seconds)
                  value = verify_response(response, counter)
                  complete = true
                  value
                ensure
                  invalidate unless complete
                end
              end
            end

            # Key wrapping never exports the session DEK. The caller must already
            # hold SD administrative authentication and explicit mutation consent.
            def wrap_key(key)
              @mutex.synchronize do
                raise ChannelError, 'Authenticated channel with a DEK required' unless authenticated? && @dek
                raise ArgumentError, 'Key material must be whole AES blocks' unless key.is_a?(String) && !key.empty? && (key.bytesize % 16).zero?

                @crypto.aes(@dek, key.b, initialization_vector: "\0".b * 16)
              end
            end

            private

            def byte(value)
              raise ArgumentError, 'KID/KVN must be integers in 0..255' unless value.is_a?(Integer) && value.between?(0, 255)

              value
            end

            def timeout(value)
              raise ArgumentError, 'Timeout must be finite and positive' unless value.is_a?(Numeric) && value.finite? && value.positive?

              value
            end

            def aes_key(value)
              raise ArgumentError, 'SCP03 requires explicit 16-byte AES keys' unless value.is_a?(String) && value.bytesize == 16

              value.b.dup
            end

            def encode(header, data, expected_length = nil, extended: false)
              raise ArgumentError, 'APDU too large for secure messaging' if data.bytesize > 65_535

              extended ||= data.bytesize > 255 || (expected_length && expected_length > 256)
              result = header.pack('C*')
              if extended
                result += [0, data.bytesize].pack('Cn') unless data.empty?
                result += data
                result += data.empty? ? [0, expected_length & 0xffff].pack('Cn') : [expected_length & 0xffff].pack('n') if expected_length
              else
                result += [data.bytesize].pack('C') + data unless data.empty?
                result += [expected_length & 0xff].pack('C') if expected_length
              end
              result
            end

            def decode(command)
              raise ArgumentError, 'Malformed APDU' unless command.is_a?(String) && command.bytesize.between?(4, 65_544)

              bytes = command.b
              header = bytes.byteslice(0, 4).bytes
              raise ArgumentError, 'Pre-wrapped secure APDUs are not accepted' unless header[0].nobits?(4)
              return [header, ''.b, nil, false] if bytes.bytesize == 4
              return [header, ''.b, bytes.getbyte(4).zero? ? 256 : bytes.getbyte(4), false] if bytes.bytesize == 5

              extended = bytes.getbyte(4).zero?
              offset = extended ? 7 : 5
              raise ArgumentError, 'Truncated extended APDU' if bytes.bytesize < offset

              length = extended ? bytes.byteslice(5, 2).unpack1('n') : bytes.getbyte(4)
              return [header, ''.b, length.zero? ? 65_536 : length, true] if extended && bytes.bytesize == 7

              remaining = bytes.bytesize - offset - length
              raise ArgumentError, 'Malformed APDU length' unless length.positive? && [0, extended ? 2 : 1].include?(remaining)

              le = if remaining.zero?
                     nil
                   else
                     bytes.byteslice(-remaining, remaining).unpack1(extended ? 'n' : 'C')
                   end
              le = extended ? 65_536 : 256 if le&.zero?
              [header, bytes.byteslice(offset, length), le, extended]
            end

            # GET RESPONSE retrieves fragments of the existing protected reply;
            # it does not start another secure command or consume its counter.
            def transmit(command, deadline)
              result = ''.b
              64.times do
                remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
                raise YubiKey::TimeoutError, 'Secure-channel exchange timed out' unless remaining.positive?

                response = @connection.exchange(protocol: :apdu, data: command, timeout: remaining)
                raise ChannelError, 'Malformed or oversized APDU response' unless response.is_a?(String) && response.bytesize.between?(2, 1_048_586)

                result += response.byteslice(0, response.bytesize - 2)
                raise ChannelError, 'Secure response size limit exceeded' if result.bytesize > 1_048_584
                return result + response.byteslice(-2, 2) unless response.getbyte(-2) == 0x61

                command = "\0\xc0\0\0".b
              end
              raise ChannelError, 'Secure response fragmentation limit exceeded'
            end

            def plain(header, data)
              response = transmit(encode(header, data), @auth_deadline)
              raise ChannelError, 'Truncated authentication response' unless response.is_a?(String) && response.bytesize >= 2
              raise ChannelError, 'Secure-channel authentication rejected' unless response.byteslice(-2, 2) == "\x90\0".b

              response.byteslice(0, response.bytesize - 2)
            end

            def initialize_scp03(keys)
              challenge = SecureRandom.random_bytes(8)
              response = plain([0x80, 0x50, @kvn, 0], challenge)
              raise ChannelError, 'Invalid SCP03 INITIALIZE UPDATE' unless [29, 32].include?(response.bytesize) && response.getbyte(11) == 3 && response.getbyte(12).nobits?(1)
              raise ChannelError, 'Unexpected SCP03 key version' unless @kvn.zero? || @kvn == response.getbyte(10)

              context = challenge + response.byteslice(13, 8)
              @enc = @crypto.derive(keys[0], 4, context)
              @mac = @crypto.derive(keys[1], 6, context)
              @rmac = @crypto.derive(keys[1], 7, context)
              expected = @crypto.derive(@mac, 0, context, 64)
              raise ChannelError, 'SCP03 card cryptogram verification failed' unless @crypto.equal?(expected, response.byteslice(21, 8))

              host = @crypto.derive(@mac, 1, context, 64)
              frame = encode([0x84, 0x82, 0x33, 0], host + ("\0".b * 8))
              @chain = @crypto.cmac(@mac, @chain + frame.byteslice(0, frame.bytesize - 8))
              reply = plain([0x84, 0x82, 0x33, 0], host + @chain.byteslice(0, 8))
              # EXTERNAL AUTHENTICATE may acknowledge with bare 9000. All
              # subsequent responses MUST authenticate their status and payload.
              verify_response(reply + "\x90\0".b, 0) unless reply.empty?
            end

            def prepare_scp11(opts)
              @kid = { scp11a: 0x11, scp11b: 0x13, scp11c: 0x15 }.fetch(@scp)
              @card_key = @crypto.ec_key(opts[:card_public_key]) if opts[:card_public_key]
              @roots = @crypto.certificates(opts[:ca_certificates]) if opts[:ca_certificates]
              raise ArgumentError, 'SCP11 needs a pinned card_public_key or explicit ca_certificates' unless @card_key || @roots

              @card_certs = @crypto.certificates(opts[:card_certificates]) if opts[:card_certificates]
              if @scp == :scp11b
                raise ArgumentError, 'SCP11b does not use OCE credentials' if opts[:oce_private_key] || opts[:oce_certificates]
              else
                @oce_key = @crypto.ec_key(opts.fetch(:oce_private_key), private_key: true)
                @oce_certs = @crypto.certificates(opts.fetch(:oce_certificates))
                public_key = @crypto.validate_chain(@oce_certs)
                raise ArgumentError, 'OCE private key does not match leaf certificate' unless @crypto.equal?(@oce_key.public_to_der, public_key.public_to_der)

                @oce_kid = byte(opts.fetch(:oce_kid, 0))
                @oce_kvn = byte(opts.fetch(:oce_kvn, 0))
                raise ArgumentError, 'Invalid OCE CA KID' unless @oce_kid.zero? || @oce_kid == 0x10 || @oce_kid.between?(0x20, 0x2f)
              end
              validate_card_certificates if @card_certs
            end

            def validate_card_certificates
              key = @crypto.validate_chain(@card_certs, @roots)
              raise ChannelError, 'Card public-key pin mismatch' if @card_key && !@crypto.equal?(@card_key.public_to_der, key.public_to_der)

              @card_key = key
            end

            def initialize_scp11
              if @roots && !@card_certs
                reference = Protocol.tlv(tag: 0xa6, value: Protocol.tlv(tag: 0x83, value: [@kid, @kvn].pack('CC')))
                raw = plain([0, 0xca, 0xbf, 0x21], reference)
                @card_certs = @crypto.certificates(Protocol.untlv(data: raw).map do |row|
                  raise ChannelError, 'Invalid certificate bundle tag' unless row[:tag] == 0x30

                  Protocol.tlv(tag: row[:tag], value: row[:value])
                end)
                validate_card_certificates
              end
              raise ArgumentError, 'OCE and card EC curves must match' if @oce_key && @oce_key.group.curve_name != @card_key.group.curve_name

              @oce_certs&.each_with_index do |cert, index|
                more = index < @oce_certs.length - 1 ? 0x80 : 0
                plain([0x80, 0x2a, @oce_kvn, @oce_kid | more], cert.to_der)
              end
              ephemeral = OpenSSL::PKey::EC.generate(@card_key.group.curve_name)
              parameters = { scp11a: 1, scp11b: 0, scp11c: 3 }.fetch(@scp)
              template = Protocol.tlv(tag: 0x90, value: [0x11, parameters].pack('CC')) + Protocol.tlv(tag: 0x95, value: "\x3c".b) + Protocol.tlv(tag: 0x80, value: "\x88".b) + Protocol.tlv(tag: 0x81, value: "\x10".b)
              data = Protocol.tlv(tag: 0xa6, value: template) + Protocol.tlv(tag: 0x5f49, value: ephemeral.public_key.to_octet_string(:uncompressed))
              ins = @scp == :scp11b ? 0x88 : 0x82
              raw_response = plain([0x80, ins, @kvn, @kid], data)
              response = Protocol.untlv(data: raw_response)
              raise ChannelError, 'Invalid SCP11 key agreement response' unless response.map { |row| row[:tag] } == [0x5f49, 0x86] && response[1][:value].bytesize == 16

              canonical = response.map { |row| Protocol.tlv(tag: row[:tag], value: row[:value]) }.join.b
              raise ChannelError, 'Noncanonical SCP11 receipt transcript' unless @crypto.equal?(raw_response, canonical)

              peer = @crypto.public_point(response[0][:value], @card_key.group.curve_name)
              secret = ephemeral.derive(peer) + (@oce_key || ephemeral).derive(@card_key)
              # ANSI X9.63 KDF: SHA256(Z || counter32be || sharedInfo).
              material = (1..3).map { |counter| OpenSSL::Digest::SHA256.digest(secret + [counter].pack('N') + "\x3c\x88\x10".b) }.join.byteslice(0, 80)
              receipt_key, @enc, @mac, @rmac, @dek = 5.times.map { |index| material.byteslice(index * 16, 16) }
              expected = @crypto.cmac(receipt_key, data + Protocol.tlv(tag: 0x5f49, value: response[0][:value]))
              raise ChannelError, 'SCP11 receipt verification failed' unless @crypto.equal?(expected, response[1][:value])

              @chain = expected
            rescue OpenSSL::OpenSSLError
              raise ChannelError, 'SCP11 key agreement failed', cause: nil
            ensure
              secret&.replace("\0".b * secret.bytesize)
              material&.replace("\0".b * material.bytesize)
              receipt_key&.replace("\0".b * receipt_key.bytesize)
            end

            def verify_response(response, counter)
              raise ChannelError, 'Missing or oversized secure response MAC' unless response.is_a?(String) && response.bytesize.between?(10, 1_048_586)

              ciphertext = response.byteslice(0, response.bytesize - 10)
              received = response.byteslice(-10, 8)
              status = response.byteslice(-2, 2)
              expected = @crypto.cmac(@rmac, @chain + ciphertext + status).byteslice(0, 8)
              raise ChannelError, 'Secure response MAC verification failed' unless @crypto.equal?(expected, received)
              raise ChannelError, 'Truncated secure ciphertext' unless (ciphertext.bytesize % 16).zero?

              data = ciphertext.empty? ? ''.b : @crypto.unpad(@crypto.aes(@enc, ciphertext, initialization_vector: @crypto.cipher_iv(@enc, counter, response: true), decrypt: true))
              data + status
            end

            def invalidate
              return if @closed

              primary = $ERROR_INFO
              @closed = true
              @ready = false
              # Best effort only: Ruby/OpenSSL/GC may retain copies. No locked
              # memory or guaranteed zeroization is claimed.
              [@enc, @mac, @rmac, @dek, @chain].compact.each { |value| value.replace("\0".b * value.bytesize) unless value.frozen? }
              @connection.close
            rescue StandardError
              raise unless primary
            end
          end

          # Authenticate a native APDU connection with explicit in-memory keys.
          public_class_method def self.open(opts = {})
            raise ArgumentError, 'connection is required' unless opts[:connection]

            Connection.new(opts)
          end

          # Return module attribution without device access.
          public_class_method def self.authors
            "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
          end

          # Describe the private implementation module without accessing a device.
          public_class_method def self.help
            puts <<~HELP
              Authenticate a native APDU connection; prefer the parent secure_connection API.
              #{self}.open(
                connection: 'required - plain native APDU transport owned by the resulting wrapper',
                scp: 'required - Symbol scp03, scp11a, scp11b or scp11c',
                kvn: 'required - exact integer key version 0..255',
                confirm: 'required - literal true permits authentication attempts',
                key_enc: 'optional - required 16-byte binary K-ENC for SCP03',
                key_mac: 'optional - required 16-byte binary K-MAC for SCP03',
                key_dek: 'optional - 16-byte binary K-DEK for SCP03 key import',
                card_public_key: 'optional - SCP11 pinned EC public key object/PEM/DER or supply CA anchors',
                ca_certificates: 'optional - trusted X509 object/PEM/DER Array for SCP11',
                card_certificates: 'optional - leaf-last X509 card bundle; otherwise fetched for CA validation',
                oce_private_key: 'optional - required EC private key object/PEM/DER for SCP11a/c',
                oce_certificates: 'optional - required leaf-last X509 OCE chain for SCP11a/c',
                oce_kid: 'optional - OCE CA KID; 0, 16 or 32..47',
                oce_kvn: 'optional - OCE CA version 0..255; default zero',
                timeout: 'optional - finite positive handshake timeout in seconds; default 30'
              )
              Return module attribution without device access.
              #{self}.authors
            HELP
          end
        end
      end
    end
  end
end
