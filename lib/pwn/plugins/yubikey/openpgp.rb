# frozen_string_literal: true

require 'openssl'

# Applet quirks and wire layouts were checked against Yubico yubikit/openpgp.py
# from YubiKey Manager 5.9.1. Attribution for that BSD-2-Clause reference follows.
# Copyright (c) 2023 Yubico AB. All rights reserved.
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

module PWN
  module Plugins
    module YubiKey
      # Native OpenPGP card protocol. No subprocesses, credential defaults or I/O at load.
      # References: OpenPGP Card 3.4; Yubico yubikit/openpgp.py 5.9.1 (BSD-2-Clause).
      module OpenPGP
        GRAMMAR = {
          'info' => [0, [], []],
          'reset' => [0, ['--force'], []],
          'access set-retries' => [3, ['--force'], []],
          'access change-pin' => [0, [], []],
          'access change-reset-code' => [0, [], []],
          'access change-admin-pin' => [0, [], []],
          'access unblock-pin' => [0, [], []],
          'access set-signature-policy' => [1, [], []],
          'keys info' => [1, [], []],
          'keys set-touch' => [2, ['--force'], []],
          'keys import' => [2, [], []],
          'keys attest' => [2, [], ['--format']],
          'certificates export' => [2, [], ['--format']],
          'certificates delete' => [1, [], []],
          'certificates import' => [2, [], []]
        }.freeze
        GROUPS = ['', 'access', 'keys', 'certificates'].freeze

        AID = ['d27600012401'].pack('H*').freeze
        SLOTS = {
          sig: { ref: 1, crt: "\xB6\0".b, attribute: 0xC1, touch: 0xD6 },
          dec: { ref: 2, crt: "\xB8\0".b, attribute: 0xC2, touch: 0xD7 },
          aut: { ref: 3, crt: "\xA4\0".b, attribute: 0xC3, touch: 0xD8 },
          att: { ref: 0x81, crt: "\xB6\x03\x84\x01\x81".b, attribute: 0xDA, touch: 0xD9 }
        }.transform_values(&:freeze).freeze
        TOUCH = { off: 0, on: 1, fixed: 2, cached: 3, 'cached-fixed': 4 }.freeze
        CURVES = {
          secp256r1: ['2a8648ce3d030107', 'prime256v1', 256, '1.2.840.10045.3.1.7'],
          secp256k1: ['2b8104000a', 'secp256k1', 256, '1.3.132.0.10'],
          secp384r1: ['2b81040022', 'secp384r1', 384, '1.3.132.0.34'],
          secp521r1: ['2b81040023', 'secp521r1', 521, '1.3.132.0.35'],
          brainpoolp256r1: ['2b2403030208010107', 'brainpoolP256r1', 256, '1.3.36.3.3.2.8.1.1.7'],
          brainpoolp384r1: ['2b240303020801010b', 'brainpoolP384r1', 384, '1.3.36.3.3.2.8.1.1.11'],
          brainpoolp512r1: ['2b240303020801010d', 'brainpoolP512r1', 512, '1.3.36.3.3.2.8.1.1.13'],
          x25519: ['2b060104019755010501', 'X25519', 255, '1.3.101.110'],
          ed25519: ['2b06010401da470f01', 'ED25519', 255, '1.3.101.112']
        }.transform_values(&:freeze).freeze

        class UnsupportedError < Error; end

        # OpenSSL objects stay in memory; raw card ECDSA uses fixed-width r || s.
        class Crypto # rubocop:disable Metrics/ClassLength
          HASH_HEADERS = {
            sha1: '3021300906052b0e03021a05000414', sha224: '302d300d06096086480165030402040500041c',
            sha256: '3031300d060960864801650304020105000420', sha384: '3041300d060960864801650304020205000430',
            sha512: '3051300d060960864801650304020305000440'
          }.freeze

          def prepare_signature(attr, message, hash_algorithm, prehashed)
            if attr[:algorithm] == :eddsa && attr[:curve] == :ed25519
              raise ArgumentError, 'Ed25519 requires the original message, not a prehash' if prehashed

              return message
            end
            raise UnsupportedError, 'The slot algorithm cannot sign messages' unless %i[rsa ecdsa].include?(attr[:algorithm])
            raise UnsupportedError, 'Unsupported signing curve' if attr[:algorithm] == :ecdsa && (!attr[:curve] || %i[x25519 ed25519].include?(attr[:curve]))
            raise UnsupportedError, 'Unsupported RSA modulus size' if attr[:algorithm] == :rsa && ![2048, 3072, 4096].include?(attr[:bits])

            name = hash_algorithm.to_s.downcase.to_sym
            header = HASH_HEADERS[name]
            raise ArgumentError, 'Unsupported signature hash algorithm' unless header

            hash = OpenSSL::Digest.new(name.to_s.upcase)
            digest = prehashed ? message : hash.digest(message)
            raise ArgumentError, 'Prehashed input has the wrong digest length' unless digest.bytesize == hash.digest_length

            attr[:algorithm] == :rsa ? [header].pack('H*') + digest : digest
          end

          def signature(attr, response)
            case attr[:algorithm]
            when :rsa
              raise ResponseError, 'Malformed RSA signature length' unless response.bytesize == attr[:bits] / 8
            when :eddsa
              raise ResponseError, 'Malformed Ed25519 signature length' unless response.bytesize == 64
            when :ecdsa
              width = (attr[:bits] + 7) / 8
              raise ResponseError, 'Malformed ECDSA signature length' unless response.bytesize == width * 2

              numbers = [response.byteslice(0, width), response.byteslice(width, width)].map { |bytes| OpenSSL::BN.new(bytes, 2) }
              order = OpenSSL::PKey::EC::Group.new(CURVES.fetch(attr[:curve])[1]).order
              raise ResponseError, 'Malformed ECDSA signature scalar' unless numbers.all? { |number| number.to_i.positive? && number < order }

              return OpenSSL::ASN1::Sequence.new(numbers.map { |number| OpenSSL::ASN1::Integer.new(number) }).to_der
            end
            response
          end

          def public_from_bytes(attr, bytes)
            curve = attr[:curve]
            entry = CURVES[curve]
            raise UnsupportedError, 'Unknown elliptic curve' unless entry

            if %i[x25519 ed25519].include?(curve)
              raise ArgumentError, 'Raw Curve25519 public key must be 32 bytes' unless bytes.bytesize == 32

              algorithm = [OpenSSL::ASN1::ObjectId.new(entry[3])]
            else
              raise ArgumentError, 'EC point length or encoding does not match the curve' unless bytes.bytesize == 1 + (2 * ((entry[2] + 7) / 8)) && bytes.getbyte(0) == 4

              algorithm = [OpenSSL::ASN1::ObjectId.new('1.2.840.10045.2.1'), OpenSSL::ASN1::ObjectId.new(entry[3])]
            end
            der = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::Sequence.new(algorithm), OpenSSL::ASN1::BitString.new(bytes)]).to_der
            key = OpenSSL::PKey.read(der)
            raise ArgumentError, 'EC point is not on the requested curve' if key.is_a?(OpenSSL::PKey::EC) && !key.public_key.on_curve?

            key
          rescue OpenSSL::OpenSSLError
            raise ArgumentError, 'Invalid public key for the requested curve', cause: nil
          end

          def parse_private(value, password)
            key = value.is_a?(OpenSSL::PKey::PKey) ? value : OpenSSL::PKey.read(value, password || '')
            if key.is_a?(OpenSSL::PKey::RSA)
              raise ArgumentError, 'RSA private key must contain factors and use exponent 65537' unless key.private? && key.e.to_i == 65_537 && key.p && key.q
              raise ArgumentError, 'Only RSA 2048, 3072 and 4096 are supported' unless [2048, 3072, 4096].include?(key.n.num_bits)
            elsif key.is_a?(OpenSSL::PKey::EC)
              raise ArgumentError, 'A valid supported EC private key is required' unless key.private? && key.check_key && CURVES.values.any? { |entry| entry[1] == key.group.curve_name }
            elsif %w[ED25519 X25519].include?(key.oid)
              raw_seed(key)
            else
              raise ArgumentError, 'Unsupported OpenPGP private key type'
            end
            key
          rescue OpenSSL::OpenSSLError, TypeError
            raise ArgumentError, 'Invalid or encrypted private key; supply key_password in memory', cause: nil
          end

          def key_algorithm(key)
            if key.is_a?(OpenSSL::PKey::RSA)
              :"rsa#{key.n.num_bits}"
            elsif key.is_a?(OpenSSL::PKey::EC)
              CURVES.find { |_name, entry| entry[1] == key.group.curve_name }.first
            else
              key.oid.downcase.to_sym
            end
          end

          def raw_seed(key)
            sequence = OpenSSL::ASN1.decode(key.private_to_der)
            value = sequence.value
            raise ArgumentError, 'Unexpected Curve25519 PKCS8 structure' unless value.is_a?(Array) && value[0].is_a?(OpenSSL::ASN1::Integer) && value[2].is_a?(OpenSSL::ASN1::OctetString)

            inner = OpenSSL::ASN1.decode(value[2].value)
            raise ArgumentError, 'Expected a 32-byte Curve25519 private seed' unless inner.is_a?(OpenSSL::ASN1::OctetString) && inner.value.bytesize == 32

            inner.value
          end

          def import_template(key, slot, format)
            if key.is_a?(OpenSSL::PKey::RSA)
              width = key.n.num_bits / 16
              components = [[0x91, key.e.to_s(2)], [0x92, key.p.to_s(2).rjust(width, "\0")], [0x93, key.q.to_s(2).rjust(width, "\0")]]
              components.push([0x94, key.iqmp.to_s(2).rjust(width, "\0")], [0x95, key.dmp1.to_s(2).rjust(width, "\0")], [0x96, key.dmq1.to_s(2).rjust(width, "\0")]) if [2, 3].include?(format)
              components << [0x97, key.n.to_s(2).rjust(width * 2, "\0")] if [1, 3].include?(format)
            elsif key.is_a?(OpenSSL::PKey::EC)
              width = (key.group.degree + 7) / 8
              components = [[0x92, key.private_key.to_s(2).rjust(width, "\0")]]
              components << [0x99, key.public_key.to_octet_string(:uncompressed)] if format == 255
            else
              seed = raw_seed(key)
              seed = seed.reverse if key.oid == 'X25519'
              components = [[0x92, seed]]
              components << [0x99, OpenSSL::ASN1.decode(key.public_to_der).value[1].value] if format == 255
            end
            headers = components.map { |tag, bytes| Protocol.tlv(tag: tag, value: bytes).byteslice(0...-bytes.bytesize) }.join.b
            values = components.map(&:last).join.b
            Protocol.tlv(tag: 0x4D, value: SLOTS.fetch(slot)[:crt] + Protocol.tlv(tag: 0x7F48, value: headers) + Protocol.tlv(tag: 0x5F48, value: values))
          end

          def public_key(attr, template)
            fields = Protocol.tlv_map(data: template)
            if attr[:algorithm] == :rsa
              modulus = fields[0x81]
              exponent = fields[0x82]
              raise ResponseError, 'Malformed RSA public key template' unless modulus && exponent && modulus.bytesize == attr[:bits] / 8 && exponent.bytesize.between?(1, 4)

              numbers = [modulus, exponent].map { |bytes| OpenSSL::BN.new(bytes, 2) }
              raise ResponseError, 'Invalid RSA public key numbers' unless numbers[0].num_bits == attr[:bits] && numbers[1].odd? && numbers[1] >= 3

              OpenSSL::PKey::RSA.new(OpenSSL::ASN1::Sequence.new(numbers.map { |number| OpenSSL::ASN1::Integer.new(number) }).to_der)
            else
              raise ResponseError, 'Missing EC public key template' unless fields[0x86]

              public_from_bytes(attr, fields.fetch(0x86))
            end
          rescue OpenSSL::OpenSSLError, ArgumentError
            raise ResponseError, 'Invalid card public key response', cause: nil
          end

          def peer_bytes(attr, value)
            raise UnsupportedError, 'Only ECDH decryption keys support key agreement' unless attr[:algorithm] == :ecdh && attr[:curve] && attr[:curve] != :ed25519

            if value.is_a?(String)
              raw = value.b
            elsif value.is_a?(OpenSSL::PKey::EC)
              raise ArgumentError, 'Peer curve differs from the card decryption curve' unless value.group.curve_name == CURVES.fetch(attr[:curve])[1]

              raw = value.public_key.to_octet_string(:uncompressed)
            elsif value.is_a?(OpenSSL::PKey::PKey) && value.oid == 'X25519' && attr[:curve] == :x25519
              raw = OpenSSL::ASN1.decode(value.public_to_der).value[1].value
            else
              raise ArgumentError, 'Peer key type or curve does not match the card decryption key'
            end
            public_from_bytes(attr, raw)
            raise ArgumentError, 'All-zero Curve25519 peer key is invalid' if attr[:curve] == :x25519 && raw.bytes.all?(&:zero?)

            raw
          end
        end

        # A request-local session never caches PINs between public calls.
        class Session # rubocop:disable Metrics/ClassLength
          def initialize(opts, reset_mode: false)
            @opts = opts.dup
            @connection = opts[:connection]
            raise ArgumentError, 'An APDU connection is required' unless @connection.respond_to?(:exchange) && @connection.descriptor[:protocol] == :apdu

            @timeout = opts.fetch(:timeout, 30)
            raise ArgumentError, 'timeout must be finite and positive' unless @timeout.is_a?(Numeric) && @timeout.finite? && @timeout.positive?

            stage = :select
            Protocol.select(connection: @connection, aid: AID, timeout: @timeout)
            stage = :version
            @version = read_version
            stage = :application
            load_application
          rescue Protocol::APDUError => e
            raise unless reset_mode && (e.status == 0x6581 || (stage == :select && [0x6285, 0x6985].include?(e.status)))

            @startup_error = e.status
          end

          def read_version
            raw = apdu(0xF1)
            raise ResponseError, 'Malformed OpenPGP firmware version' unless raw.bytesize == 3

            raw.bytes.map { |byte| bcd(byte) }
          rescue Protocol::APDUError => e
            raise unless e.status == 0x6985

            [1, 0, 0] # Documented pre-1.0.2 NEO applets lack GET VERSION.
          end

          def apdu(ins, param1 = 0, param2 = 0, data = ''.b, cla: 0)
            Protocol.apdu(connection: @connection, ins: ins, p1: param1, p2: param2, data: data, cla: cla, timeout: @timeout)
          end

          def get_data(tag)
            apdu(0xCA, tag >> 8, tag & 0xFF)
          end

          def put_data(tag, value)
            apdu(0xDA, tag >> 8, tag & 0xFF, value)
          end

          def unpack(tag, bytes)
            fields = Protocol.tlv_map(data: bytes)
            raise ResponseError, 'Unexpected OpenPGP response template' unless fields.keys == [tag]

            fields.fetch(tag)
          end

          def bcd(byte)
            raise ResponseError, 'Invalid OpenPGP BCD version' unless (byte >> 4) <= 9 && (byte & 15) <= 9

            ((byte >> 4) * 10) + (byte & 15)
          end

          def load_application
            outer = Protocol.tlv_map(data: unpack(0x6E, get_data(0x6E)))
            @aid = outer.fetch(0x4F) { raise ResponseError, 'OpenPGP AID absent' }
            raise ResponseError, 'Malformed OpenPGP AID' unless @aid.bytesize == 16 && @aid.start_with?(AID)

            @card_version = @aid.byteslice(6, 2).bytes.map { |byte| bcd(byte) }
            @objects = outer[0x73] && outer[0x73].empty? ? outer : Protocol.tlv_map(data: outer.fetch(0x73) { raise ResponseError, 'Discretionary data absent' })
            capabilities = @objects.fetch(0xC0) { raise ResponseError, 'Extended capabilities absent' }
            raise ResponseError, 'Malformed extended capabilities' unless capabilities.bytesize == 10

            @flags = capabilities.getbyte(0)
            @certificate_max = capabilities.byteslice(4, 2).unpack1('n')
            @pin_status = pin_status(@objects.fetch(0xC4) { raise ResponseError, 'PIN status absent' })
            @historical = outer[0x5F52]
          end

          def pin_status(data = get_data(0xC4))
            raise ResponseError, 'Malformed PIN status' unless data.bytesize == 7

            bytes = data.bytes
            { signature_policy: { 0 => :always, 1 => :once }.fetch(bytes[0], :unknown),
              max_user: bytes[1], max_reset: bytes[2], max_admin: bytes[3], user: bytes[4], reset: bytes[5], admin: bytes[6] }
          end

          def attributes(data)
            raise ResponseError, 'Empty algorithm attributes' if data.nil? || data.empty?

            case data.getbyte(0)
            when 1
              raise ResponseError, 'Malformed RSA attributes' unless data.bytesize == 6

              _, bits, exponent_bits, import_format = data.unpack('CnnC')
              { algorithm: :rsa, bits: bits, exponent_bits: exponent_bits, import_format: import_format, encoded: data }
            when 0x12, 0x13, 0x16
              oid = data.byteslice(1..)
              with_public = oid.end_with?("\xFF".b)
              oid = oid.byteslice(0...-1) if with_public
              curve = CURVES.find { |_name, entry| entry[0] == oid.unpack1('H*') }&.first
              { algorithm: { 0x12 => :ecdh, 0x13 => :ecdsa, 0x16 => :eddsa }.fetch(data.getbyte(0)), curve: curve,
                oid: oid.unpack1('H*'), bits: curve && CURVES.fetch(curve)[2], import_format: with_public ? 255 : 0, encoded: data }
            else
              { algorithm: :unknown, algorithm_id: data.getbyte(0), encoded: data }
            end
          end

          def key_info(slot)
            definition = SLOTS.fetch(slot)
            data = @objects[definition[:attribute]]
            raise UnsupportedError, 'Key slot is not supported by this card' unless data

            status = @objects[0xDE].to_s.b
            raise ResponseError, 'Malformed key information' unless status.bytesize.even?

            origin = status.bytes.each_slice(2).to_h[definition[:ref]]
            index = SLOTS.keys.index(slot)
            touch_data = @objects[definition[:touch]]
            touch_data = get_data(definition[:touch]) if touch_data.nil? && @card_version[0] < 3 && @version && Protocol.version_at_least?(version: @version, minimum: [4, 2, 0])
            raise ResponseError, 'Malformed touch policy' if touch_data && (touch_data.bytesize != 2 || !TOUCH.value?(touch_data.getbyte(0)))

            attributes(data).merge(slot: slot, origin: { 0 => :none, 1 => :generated, 2 => :imported }.fetch(origin, :unknown),
                                   fingerprint: @objects[0xC5]&.byteslice(index * 20, 20)&.unpack1('H*'),
                                   generated_at: @objects[0xCD]&.byteslice(index * 4, 4)&.unpack1('N'),
                                   touch: touch_data && TOUCH.key(touch_data.getbyte(0)))
          end

          def secret(name)
            Protocol.secret(value: @opts[name], name: name, secret_provider: @opts[:secret_provider])
          end

          def pin_bytes(name, role)
            value = secret(name).b
            raise ArgumentError, 'PIN input is too large' if value.bytesize > 4096

            # The KDF object is read once per request, never inferred from PIN length.
            if @flags.anybits?(1)
              @kdf ||= Protocol.tlv_map(data: get_data(0xF9))
              algorithm = @kdf[0x81]
              unless algorithm.nil? || algorithm == "\0".b
                raise UnsupportedError, 'Unsupported card PIN KDF' unless algorithm == "\x03".b

                digest_name = { "\x08".b => 'SHA256', "\x0A".b => 'SHA512' }[@kdf[0x82]]
                count_bytes = @kdf[0x83]
                salt = @kdf[{ user: 0x84, reset: 0x85, admin: 0x86 }.fetch(role)] || @kdf[0x84]
                raise ResponseError, 'Malformed card PIN KDF' unless digest_name && count_bytes&.bytesize == 4 && salt&.bytesize == 8

                count = count_bytes.unpack1('N')
                raise UnsupportedError, 'Card PIN KDF byte count is outside the supported bound' unless count.between?(1, 67_108_864)

                source = salt + value
                digest = OpenSSL::Digest.new(digest_name)
                # RFC 4880 iterated-and-salted S2K hashes at least one full source.
                remaining = [count, source.bytesize].max
                chunk = source * [65_536 / source.bytesize, 1].max
                while remaining.positive?
                  take = [remaining, chunk.bytesize].min
                  digest.update(chunk.byteslice(0, take))
                  remaining -= take
                end
                value = digest.digest
              end
            end
            min = role == :user ? 6 : 8
            max = @pin_status.fetch(:"max_#{role}")
            raise ArgumentError, "#{name} length must be #{min}..#{max} bytes" unless value.bytesize.between?(min, max)

            value
          end

          def require_version(minimum, capability)
            return if Protocol.version_at_least?(version: @version, minimum: minimum)

            raise UnsupportedError, "#{capability} is not supported by this firmware"
          end

          def verify_admin
            apdu(0x20, 0, 0x83, pin_bytes(:admin_pin, :admin))
          end

          def configure_retries(counts)
            require_version(@version[0] == 1 ? [1, 0, 7] : [4, 3, 1], 'Setting PIN retries')
            verify_admin
            apdu(0xF2, 0, 0, counts.pack('C*'))
            status = pin_status
            raise ResponseError, 'PIN retries readback mismatch; mutation was not replayed' unless status.values_at(:user, :reset, :admin) == counts

            { pin_status: status, verified: true, pins_reset: @version[0] < 4 }
          end

          def change_reset_code
            reset = pin_bytes(:reset_code, :reset)
            verify_admin
            put_data(0xD3, reset)
            { changed: :reset_code, pin_status: pin_status, credential_verified: false }
          end

          def unblock_pin
            replacement = pin_bytes(:new_pin, :user)
            if @opts[:admin_pin] || @opts[:use_admin] == true
              verify_admin
              apdu(0x2C, 2, 0x81, replacement)
            else
              reset = pin_bytes(:reset_code, :reset)
              apdu(0x2C, 0, 0x81, reset + replacement)
            end
            { unblocked: true, pin_status: pin_status, credential_verified: false }
          end

          def signature_policy(policy)
            raise UnsupportedError, 'Changing the signature PIN policy is unsupported' if @flags.nobits?(0x10)

            verify_admin
            put_data(0xC4, [policy == :always ? 0 : 1].pack('C'))
            status = pin_status
            raise ResponseError, 'Signature policy readback mismatch; mutation was not replayed' unless status[:signature_policy] == policy

            { signature_policy: policy, verified: true, pin_status: status }
          end

          def change_pin(admin: false)
            role = admin ? :admin : :user
            name = admin ? :admin_pin : :pin
            current = pin_bytes(name, role)
            replacement = pin_bytes(admin ? :new_admin_pin : :new_pin, role)
            apdu(0x24, 0, admin ? 0x83 : 0x81, current + replacement)
            { changed: name, pin_status: pin_status, credential_verified: false }
          end

          def algorithm_attributes(slot, algorithm)
            if algorithm.to_s.start_with?('rsa')
              [1, algorithm.to_s.delete_prefix('rsa').to_i, 17, @version[0] < 4 ? 3 : 0].pack('CnnC')
            else
              raise ArgumentError, 'X25519 is only valid in the decryption slot' if algorithm == :x25519 && slot != :dec
              raise ArgumentError, 'Ed25519 is not valid in the decryption or attestation slot' if algorithm == :ed25519 && %i[dec att].include?(slot)

              require_version([5, 2, 0], 'Elliptic curve keys')
              id = if algorithm == :ed25519
                     0x16
                   else
                     (slot == :dec ? 0x12 : 0x13)
                   end
              [id].pack('C') + [CURVES.fetch(algorithm)[0]].pack('H*')
            end
          end

          def algorithms
            return SLOTS.keys.select { |slot| @objects[SLOTS[slot][:attribute]] }.to_h { |slot| [slot, [attributes(@objects[SLOTS[slot][:attribute]])]] } if @flags.nobits?(4)

            unless Protocol.version_at_least?(version: @version, minimum: [5, 2, 0])
              sizes = @version[0] < 4 || @version.take(2) == [4, 4] ? [2048] : [2048, 3072, 4096]
              return %i[sig dec aut].to_h { |slot| [slot, sizes.map { |bits| attributes(algorithm_attributes(slot, :"rsa#{bits}")) }] }
            end
            raw = get_data(0xFA)
            rows = Protocol.untlv(data: algorithm_information_body(raw))
            result = {}
            rows.each do |row|
              slot = SLOTS.find { |_name, entry| entry[:attribute] == row[:tag] }&.first
              raise ResponseError, 'Unknown key slot in algorithm information' unless slot

              (result[slot] ||= []) << attributes(row[:value])
            end
            unless Protocol.version_at_least?(version: @version, minimum: [5, 6, 1])
              # Published Yubico firmware erratum: X25519 was advertised as EdDSA.
              bad_x = result.values.flatten.any? { |entry| entry[:curve] == :x25519 && entry[:algorithm] == :eddsa }
              result.each do |slot, entries|
                entries.reject! { |entry| (entry[:curve] == :x25519 && entry[:algorithm] != :ecdh) || (%i[dec att].include?(slot) && entry[:curve] == :ed25519) }
              end
              if bad_x && result[:dec]
                fixed = attributes(algorithm_attributes(:dec, :x25519))
                result[:dec] << fixed unless result[:dec].any? { |entry| entry[:encoded] == fixed[:encoded] }
              end
            end
            result
          end

          def algorithm_information_body(raw)
            unpack(0xFA, raw)
          rescue ResponseError
            raise if Protocol.version_at_least?(version: @version, minimum: [5, 6, 1])

            # The old applet's outer FA length includes two nonexistent SW bytes.
            # Strict unpack still rejects every length difference other than +2.
            unpack(0xFA, raw + "\0\0".b).byteslice(0...-2)
          end

          def validate_key_attributes(slot, encoded)
            current = key_info(slot)
            desired = attributes(encoded)
            return attributes(current[:encoded]) if @flags.nobits?(4) && current[:algorithm] == :rsa && desired[:algorithm] == :rsa && current[:bits] == 2048 && desired[:bits] == 2048

            supported = algorithms.fetch(slot, [])
            # Prefer standard import; some cards advertise the same curve with public-point import.
            match = supported.find { |entry| entry[:encoded] == encoded }
            match ||= supported.find { |entry| desired[:curve] && entry[:curve] == desired[:curve] && entry[:algorithm] == desired[:algorithm] && entry[:import_format] == 255 }
            raise UnsupportedError, 'Algorithm or key slot is not supported by this card' unless match

            match
          end

          def write_attributes(slot, attr)
            tag = SLOTS.fetch(slot)[:attribute]
            return if @objects[tag] == attr[:encoded]

            raise UnsupportedError, 'Algorithm attributes cannot be changed on this card' if @flags.nobits?(4)

            put_data(tag, attr[:encoded])
            raise ResponseError, 'Key algorithm attributes readback mismatch; mutation was not replayed' unless get_data(tag) == attr[:encoded]

            @objects[tag] = attr[:encoded]
          end

          def public_key(slot, attr = key_info(slot))
            raw = apdu(0x47, 0x81, 0, SLOTS.fetch(slot)[:crt])
            Crypto.new.public_key(attr, unpack(0x7F49, raw))
          end

          def generate_key(slot, algorithm)
            raise UnsupportedError, 'RSA generation is disabled on vulnerable firmware; update or import a host-generated key' if algorithm.to_s.start_with?('rsa') && Protocol.version_at_least?(version: @version, minimum: [4, 2, 0]) && !Protocol.version_at_least?(version: @version, minimum: [4, 3, 5])

            attr = validate_key_attributes(slot, algorithm_attributes(slot, algorithm))
            verify_admin
            write_attributes(slot, attr)
            raw = apdu(0x47, 0x80, 0, SLOTS.fetch(slot)[:crt])
            key = Crypto.new.public_key(attr, unpack(0x7F49, raw))
            raise ResponseError, 'Generated public key readback mismatch; generation was not replayed' unless public_key(slot, attr).public_to_der == key.public_to_der

            key
          end

          def import_key(slot, key)
            raise UnsupportedError, 'Key import is not supported by this card' if @flags.nobits?(0x20)

            crypto = Crypto.new
            attr = validate_key_attributes(slot, algorithm_attributes(slot, crypto.key_algorithm(key)))
            format = key.is_a?(OpenSSL::PKey::RSA) && @version[0] < 4 ? 3 : attr[:import_format]
            template = crypto.import_template(key, slot, format)
            verify_admin
            write_attributes(slot, attr)
            apdu(0xDB, 0x3F, 0xFF, template)
            actual = public_key(slot, attr)
            raise ResponseError, 'Imported public key readback mismatch; import was not replayed' unless actual.public_to_der == key.public_to_der

            { imported: :key, slot: slot, verified: true, public_key: actual }
          end

          def block_for_reset(role, reference)
            remaining = @pin_status.fetch(role)
            remaining.times do
              begin
                apdu(0x20, 0, reference, "\0".b * 8)
                raise ResponseError, 'Reset sentinel unexpectedly verified; reset aborted without guessing another PIN'
              rescue Protocol::APDUError => e
                raise unless [0x6982, 0x6983].include?(e.status) || (e.status & 0xFFF0) == 0x63C0
              end
              observed = pin_status.fetch(role)
              raise ResponseError, 'Reset retry counter did not decrease; reset aborted' unless observed < remaining

              remaining = observed
              break if remaining.zero?
            end
            raise ResponseError, 'PIN did not block; reset aborted' unless remaining.zero?
          end

          def block_corrupt_for_reset(reference)
            # Retry counters are unreadable: this is deliberate blocking, not an
            # authentication retry. A one-byte card counter bounds attempts to 255.
            256.times do
              apdu(0x20, 0, reference, "\0".b * 8)
              raise ResponseError, 'Reset sentinel unexpectedly verified; reset aborted'
            rescue Protocol::APDUError => e
              return if [0x6983, 0x63C0].include?(e.status)
              raise unless e.status == 0x6982 || (e.status & 0xFFF0) == 0x63C0
            end
            raise ResponseError, 'Reset blocking exceeded card counter bound; reset aborted'
          end

          def reset
            if @startup_error == 0x6581
              block_corrupt_for_reset(0x81)
              block_corrupt_for_reset(0x83)
              apdu(0xE6)
            elsif !@startup_error
              require_version([1, 0, 6], 'OpenPGP reset')
              block_for_reset(:user, 0x81)
              block_for_reset(:admin, 0x83)
              apdu(0xE6)
            end
            apdu(0x44)
            Protocol.select(connection: @connection, aid: AID, timeout: @timeout)
            load_application
            clear = %i[sig dec aut].all? do |slot|
              info = key_info(slot)
              %i[none unknown].include?(info[:origin]) && info[:fingerprint] == '00' * 20
            end
            raise ResponseError, 'OpenPGP reset readback still contains keys; reset was not replayed' unless clear

            { reset: true, key_slots_verified_empty: true, pin_status: @pin_status, attestation_preserved: true }
          end

          def set_touch(slot, policy)
            require_version([4, 2, 0], 'Touch policy')
            require_version([5, 2, 1], 'Cached or attestation touch policy') if slot == :att || [3, 4].include?(TOUCH.fetch(policy))
            key_info(slot)
            tag = SLOTS.fetch(slot)[:touch]
            current = get_data(tag)
            raise ResponseError, 'Malformed touch policy' unless current.bytesize == 2 && TOUCH.value?(current.getbyte(0))
            raise UnsupportedError, 'A fixed touch policy cannot be changed without replacing the key' if [2, 4].include?(current.getbyte(0))

            verify_admin
            value = [TOUCH.fetch(policy), 0x20].pack('CC')
            put_data(tag, value)
            raise ResponseError, 'Touch policy readback mismatch; mutation was not replayed' unless get_data(tag) == value

            { slot: slot, touch: policy, irreversible: [2, 4].include?(TOUCH.fetch(policy)), verified: true }
          end

          def certificate_supported(slot)
            return if slot == :aut

            require_version([5, 2, 0], 'Certificate slot')
          end

          def select_certificate(slot)
            certificate_supported(slot)
            return if slot == :att || !Protocol.version_at_least?(version: @version, minimum: [5, 2, 0])

            value = "\x60\x04\x5C\x02\x7F\x21".b
            value = "\x06".b + value unless Protocol.version_at_least?(version: @version, minimum: [5, 4, 4])
            apdu(0xA5, 3 - SLOTS.fetch(slot)[:ref], 4, value)
          end

          def certificate_bytes(slot)
            select_certificate(slot)
            get_data(slot == :att ? 0xFC : 0x7F21)
          end

          def export_certificate(slot, format)
            raw = certificate_bytes(slot)
            raise ResponseError, 'No certificate stored in the selected slot' if raw.empty?

            cert = OpenSSL::X509::Certificate.new(raw)
            format == :der ? cert.to_der : cert.to_pem
          rescue OpenSSL::X509::CertificateError
            raise ResponseError, 'Stored certificate is not valid X.509 DER', cause: nil
          end

          def write_certificate(slot, raw)
            certificate_supported(slot)
            raise UnsupportedError, 'Certificate exceeds the card certificate limit' if raw.bytesize > @certificate_max

            verify_admin
            select_certificate(slot)
            put_data(slot == :att ? 0xFC : 0x7F21, raw)
            raise ResponseError, 'Certificate readback mismatch; mutation was not replayed' unless certificate_bytes(slot) == raw

            { (raw.empty? ? :deleted : :imported) => :certificate, slot: slot, verified: true }
          end

          def attest_key(slot, format)
            require_version([5, 2, 0], 'Key attestation')
            raise UnsupportedError, 'Only on-card generated keys can be attested' if %i[none imported].include?(key_info(slot)[:origin])

            verify_user
            apdu(0xFB, SLOTS.fetch(slot)[:ref], 0, ''.b, cla: 0x80)
            export_certificate(slot, format)
          end

          def sign(message, hash_algorithm, prehashed: false, authentication: false)
            attr = key_info(authentication ? :aut : :sig)
            raise UnsupportedError, 'The selected key slot is empty' if attr[:origin] == :none

            crypto = Crypto.new
            encoded = crypto.prepare_signature(attr, message, hash_algorithm, prehashed)
            raise ArgumentError, 'Signing payload length exceeds the APDU limit' if encoded.bytesize > 65_535

            verify_user(authentication ? 0x82 : 0x81)
            response = authentication ? apdu(0x88, 0, 0, encoded) : apdu(0x2A, 0x9E, 0x9A, encoded)
            crypto.signature(attr, response)
          end

          def decipher(value)
            attr = key_info(:dec)
            raise UnsupportedError, 'The decryption key slot is empty' if attr[:origin] == :none

            if attr[:algorithm] == :rsa
              raise ArgumentError, 'RSA ciphertext length must equal the key modulus length' unless value.is_a?(String) && value.bytesize == attr[:bits] / 8

              encoded = "\0".b + value.b
            else
              peer = Crypto.new.peer_bytes(attr, value)
              encoded = Protocol.tlv(tag: 0xA6, value: Protocol.tlv(tag: 0x7F49, value: Protocol.tlv(tag: 0x86, value: peer)))
            end
            verify_user(0x82)
            response = apdu(0x2A, 0x80, 0x86, encoded)
            if attr[:algorithm] == :ecdh
              width = (attr[:bits] + 7) / 8
              raise ResponseError, 'Invalid card ECDH secret length or all-zero result' unless response.bytesize == width && response.bytes.any?(&:positive?)
            end
            response
          end

          def verify_pin(mode)
            if mode == :admin
              verify_admin
            else
              verify_user(mode == :extended ? 0x82 : 0x81)
            end
            { verified: true, mode: mode }
          end

          def unverify_pin(mode)
            require_version([5, 6, 0], 'PIN reset-verification')
            apdu(0x20, 0xFF, { signature: 0x81, extended: 0x82, admin: 0x83 }.fetch(mode))
            { cleared: mode }
          end

          def verify_user(reference = 0x81)
            encoded = pin_bytes(:pin, :user)
            apdu(0x20, 0, reference, encoded)
          end

          def kdf_enabled?
            return false if @flags.nobits?(1)

            @kdf ||= Protocol.tlv_map(data: get_data(0xF9))
            @kdf.key?(0x81) && @kdf[0x81] != "\0".b
          end

          def info
            counter = Protocol.tlv_map(data: unpack(0x7A, get_data(0x7A))).fetch(0x93) { raise ResponseError, 'Signature counter absent' }
            raise ResponseError, 'Malformed signature counter' unless counter.bytesize == 3

            { application: :openpgp, firmware: @version, card_version: @card_version, aid: @aid.unpack1('H*'),
              manufacturer: @aid.byteslice(8, 2).unpack1('n'), pin_status: @pin_status,
              signature_counter: counter.unpack1('H*').to_i(16), extended_capabilities: @flags, kdf_enabled: kdf_enabled?,
              certificate_max_length: @certificate_max, keys: SLOTS.keys.select { |slot| @objects[SLOTS[slot][:attribute]] }.to_h { |slot| [slot, key_info(slot)] } }
          end
        end

        private_constant :Session, :Crypto

        public_class_method def self.operations
          GRAMMAR.keys.freeze
        end

        public_class_method def self.execute(opts = {})
          args = opts[:args] || []
          raise ArgumentError, 'args must be an Array of Strings' unless args.is_a?(Array) && args.all?(String)

          group = args.join(' ')
          return { application: :openpgp, group: group, operations: operations } if GROUPS.include?(group)

          path = GRAMMAR.keys.sort_by { |entry| -entry.split.size }.find { |entry| args.take(entry.split.size) == entry.split }
          raise ArgumentError, 'Unknown OpenPGP operation' unless path
          raise ArgumentError, 'Credentials must be supplied in memory, never argv' if args.any? { |arg| arg.match?(/\A--(?:pin|admin-pin|reset-code|new-pin|new-admin-pin|password)(?:=|\z)/) }

          count, flags, values = GRAMMAR.fetch(path)
          parsed = Protocol.parse_args(args: args.drop(path.split.size), flags: flags, values: values)
          raise ArgumentError, 'Unexpected number of OpenPGP arguments' unless parsed[:positionals].length == count

          positionals = parsed[:positionals]
          if path == 'access set-retries'
            raise ArgumentError, 'PIN retries must be integers from 1 to 99' unless positionals.all? { |value| value.match?(/\A[1-9][0-9]?\z/) }
          elsif path == 'access set-signature-policy'
            raise ArgumentError, 'Signature policy must be always or once' unless %w[always once].include?(positionals[0])
          elsif path == 'access unblock-pin' && opts[:reset_code] && (opts[:admin_pin] || opts[:use_admin] == true)
            raise ArgumentError, 'Choose either reset code or admin PIN, not both'
          end
          slot = validate_slot(slot: positionals[0]) if path.start_with?('keys ', 'certificates ')
          policy = positionals[1]&.to_sym if path == 'keys set-touch'
          raise ArgumentError, 'Unknown touch policy' if policy && !TOUCH.key?(policy)
          raise ArgumentError, 'The attestation key cannot attest itself' if path == 'keys attest' && slot == :att

          raw_format = parsed[:options][:format] || 'PEM'
          raise ArgumentError, 'Supply exactly one certificate format' unless raw_format.is_a?(String)

          format = raw_format.downcase.to_sym
          raise ArgumentError, 'Certificate format must be PEM or DER' unless %i[pem der].include?(format)

          output = positionals[1] if ['keys attest', 'certificates export'].include?(path)
          if output && output != '-'
            raise ArgumentError, 'Output path already exists; refusing to overwrite' if File.exist?(output) || File.symlink?(output)
            raise ArgumentError, 'Output parent directory must exist and be writable' unless File.directory?(File.dirname(output)) && File.writable?(File.dirname(output))
          end
          certificate = parse_certificate(data: input_bytes(path: positionals[1], value: opts[:certificate])) if path == 'certificates import'
          Protocol.require_confirm(opts) unless ['info', 'keys info', 'certificates export'].include?(path)
          key = load_private_key(opts.merge(key: input_bytes(path: positionals[1], value: opts[:key]))) if path == 'keys import'
          session = Session.new(opts, reset_mode: path == 'reset')
          result = case path
                   when 'info' then session.info
                   when 'reset' then session.reset
                   when 'access change-pin' then session.change_pin
                   when 'access change-admin-pin' then session.change_pin(admin: true)
                   when 'access set-retries' then session.configure_retries(positionals.map(&:to_i))
                   when 'access change-reset-code' then session.change_reset_code
                   when 'access unblock-pin' then session.unblock_pin
                   when 'access set-signature-policy' then session.signature_policy(positionals[0].to_sym)
                   when 'keys info' then session.key_info(slot)
                   when 'keys set-touch' then session.set_touch(slot, policy)
                   when 'keys import' then session.import_key(slot, key)
                   when 'keys attest' then session.attest_key(slot, format)
                   when 'certificates export' then session.export_certificate(slot, format)
                   when 'certificates import' then session.write_certificate(slot, certificate.to_der)
                   when 'certificates delete' then session.write_certificate(slot, ''.b)
                   else raise ArgumentError, 'Unknown OpenPGP operation'
                   end
          File.open(output, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(result) } if output && output != '-'
          result
        end

        private_class_method def self.validate_slot(opts = {})
          value = opts[:slot]
          slot = value.to_s.downcase.to_sym
          slot = :dec if slot == :enc
          raise ArgumentError, 'slot must be sig, dec, aut or att' unless SLOTS.key?(slot)

          slot
        end

        private_class_method def self.input_bytes(opts = {})
          path = opts[:path]
          value = opts[:value]
          if path && path != '-'
            raise ArgumentError, 'Supply a file path or in-memory data, not both' if value

            value = File.binread(path, 1_048_577)
          end
          raise ArgumentError, 'Supply bounded PEM or DER bytes in memory when using -' unless value.is_a?(String) && value.bytesize.between?(1, 1_048_576)

          value.b
        end

        private_class_method def self.parse_certificate(opts = {})
          bytes = opts[:data]
          if bytes.include?('-----BEGIN')
            raise ArgumentError, 'Supply exactly one PEM certificate' unless bytes.scan('-----BEGIN CERTIFICATE-----').size == 1 && bytes.match?(%r{\A\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*\z})
          else
            OpenSSL::ASN1.decode(bytes)
          end
          OpenSSL::X509::Certificate.new(bytes)
        rescue OpenSSL::OpenSSLError
          raise ArgumentError, 'Certificate is not valid PEM or DER X.509', cause: nil
        end

        private_class_method def self.load_private_key(opts = {})
          value = opts[:key]
          raise ArgumentError, 'key must be PEM/DER bytes or an OpenSSL private key' unless value.is_a?(OpenSSL::PKey::PKey) || (value.is_a?(String) && value.bytesize.between?(1, 1_048_576))

          password = opts[:key_password]
          encrypted = value.is_a?(String) && value.include?('ENCRYPTED')
          if value.is_a?(String) && !value.include?('-----BEGIN')
            begin
              data = OpenSSL::ASN1.decode(value).value
              encrypted ||= data.is_a?(Array) && data.first.is_a?(OpenSSL::ASN1::Sequence) && data[1].is_a?(OpenSSL::ASN1::OctetString)
            rescue OpenSSL::ASN1::ASN1Error
              raise ArgumentError, 'Malformed private key encoding', cause: nil
            end
          end
          password = Protocol.secret(value: password, name: :key_password, secret_provider: opts[:secret_provider]) if encrypted
          Crypto.new.parse_private(value, password)
        end

        public_class_method def self.generate_key(opts = {})
          slot = validate_slot(slot: opts[:slot])
          algorithm = opts[:algorithm].to_s.downcase.to_sym
          raise ArgumentError, 'Unknown key algorithm; use rsa2048/rsa3072/rsa4096 or a named curve' unless [:rsa2048, :rsa3072, :rsa4096, *CURVES.keys].include?(algorithm)

          Protocol.require_confirm(opts)
          Session.new(opts).generate_key(slot, algorithm)
        end

        public_class_method def self.import_key(opts = {})
          slot = validate_slot(slot: opts[:slot])
          Protocol.require_confirm(opts)
          key = load_private_key(opts)
          Session.new(opts).import_key(slot, key)
        end

        public_class_method def self.sign(opts = {})
          message = opts[:message]
          raise ArgumentError, 'message must be a bounded binary String' unless message.is_a?(String) && message.bytesize <= 1_048_576

          Protocol.require_confirm(opts)
          Session.new(opts).sign(message.b, opts.fetch(:hash_algorithm, :sha256), prehashed: opts[:prehashed] == true)
        end

        public_class_method def self.authenticate(opts = {})
          message = opts[:message]
          raise ArgumentError, 'message must be a bounded binary String' unless message.is_a?(String) && message.bytesize <= 1_048_576

          Protocol.require_confirm(opts)
          Session.new(opts).sign(message.b, opts.fetch(:hash_algorithm, :sha256), prehashed: opts[:prehashed] == true, authentication: true)
        end

        public_class_method def self.decipher(opts = {})
          value = opts[:value]
          raise ArgumentError, 'value must be ciphertext bytes or an OpenSSL peer public key' unless value.is_a?(String) || value.is_a?(OpenSSL::PKey::PKey)

          Protocol.require_confirm(opts)
          Session.new(opts).decipher(value)
        end

        public_class_method def self.algorithms(opts = {})
          Session.new(opts.merge(connection: opts[:connection])).algorithms
        end

        public_class_method def self.public_key(opts = {})
          slot = validate_slot(slot: opts[:slot])
          Session.new(opts).public_key(slot)
        end

        public_class_method def self.verify_pin(opts = {})
          mode = opts[:mode] || :signature
          raise ArgumentError, 'mode must be :signature, :extended or :admin' unless %i[signature extended admin].include?(mode)

          Protocol.require_confirm(opts)
          Session.new(opts).verify_pin(mode)
        end

        public_class_method def self.unverify_pin(opts = {})
          mode = opts[:mode] || :signature
          raise ArgumentError, 'mode must be :signature, :extended or :admin' unless %i[signature extended admin].include?(mode)

          Protocol.require_confirm(opts)
          Session.new(opts).unverify_pin(mode)
        end

        public_class_method def self.decrypt(opts = {})
          decipher(opts.merge(value: opts[:value]))
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~HELP
            Native Ruby OpenPGP Card application over a caller-owned APDU Connection.
            All authentication, key use, mutation and reset operations require confirm: true.
            Credentials stay in memory. There are no factory credentials or automatic mutation retries.
            Changing key attributes can erase an existing key; fixed touch policies are irreversible
            until that key is replaced. Reset preserves the attestation key and certificate.
            PIN change results report fresh counters, not proof of the new secret value.

            List implemented management leaf paths without accessing hardware.
            #{self}.operations
            Execute a native management operation or list a local group.
            #{self}.execute(
              args: 'optional - Nonsecret words after openpgp; groups are access, keys and certificates',
              connection: 'required - Caller-owned YubiKey Connection with descriptor protocol :apdu',
              timeout: 'optional - Finite positive per-command timeout in seconds; default 30',
              confirm: 'optional - Literal true required for authentication, cryptographic use and every mutation',
              pin: 'optional - Current user PIN bytes supplied directly in memory',
              new_pin: 'optional - New user PIN bytes for change-pin or unblock-pin',
              admin_pin: 'optional - Current admin PIN bytes supplied directly in memory',
              new_admin_pin: 'optional - Replacement admin PIN bytes for change-admin-pin',
              reset_code: 'optional - Reset code bytes for change-reset-code or unblock-pin',
              use_admin: 'optional - Literal true selects provider-supplied admin authorization for unblock-pin',
              key: 'optional - PEM or DER private key bytes when keys import uses the input marker -',
              key_password: 'optional - Private key decryption password kept in memory, never argv',
              certificate: 'optional - One PEM or DER certificate when certificates import uses -',
              secret_provider: 'optional - Callable receiving a required secret field Symbol and returning bytes'
            )
            Leaves: info; reset [--force]; access set-retries USER RESET ADMIN;
            access change-pin; access change-admin-pin; access change-reset-code;
            access unblock-pin; access set-signature-policy always|once;
            keys info SLOT; keys set-touch SLOT off|on|fixed|cached|cached-fixed [--force];
            keys import SLOT FILE|-; keys attest SLOT OUTPUT|- [--format PEM|DER];
            certificates export SLOT OUTPUT|- [--format PEM|DER];
            certificates import SLOT FILE|-; certificates delete SLOT.
            --force is syntax compatibility, never consent. Input - requires in-memory data;
            output - returns bytes, never writes stdout. Named output paths are created exclusively.

            Query firmware-specific algorithms advertised by the selected card.
            #{self}.algorithms(connection: connection)
            Export a slot public key as a native OpenSSL public-key object.
            #{self}.public_key(slot: :sig, connection: connection)
            Generate an on-card private key and verify its public-key readback.
            #{self}.generate_key(
              slot: 'required - Key slot :sig, :dec, :aut or :att; :enc aliases :dec',
              algorithm: 'required - rsa2048, rsa3072, rsa4096, secp256r1, secp256k1, secp384r1, secp521r1, brainpoolp256r1, brainpoolp384r1, brainpoolp512r1, ed25519 or x25519',
              connection: connection, admin_pin: admin_pin, confirm: true
            )
            Import a native OpenSSL private key or PEM/DER bytes and verify its public key.
            #{self}.import_key(slot: :sig, key: key, connection: connection, admin_pin: admin_pin, confirm: true)
            Sign a message with the signature slot using PSO COMPUTE DIGITAL SIGNATURE.
            #{self}.sign(
              message: 'required - Original binary message; Ed25519 is not prehashed',
              hash_algorithm: 'optional - sha1, sha224, sha256, sha384 or sha512; defaults to sha256 and is ignored for Ed25519',
              prehashed: 'optional - Literal true means message already contains the named digest; not valid for Ed25519',
              connection: connection, pin: pin, confirm: true
            )
            Sign an authentication challenge with the authentication slot using INTERNAL AUTHENTICATE.
            #{self}.authenticate(message: message, connection: connection, pin: pin, confirm: true)
            Decrypt an RSA PKCS1-v1_5 block or perform raw ECDH with the decryption slot.
            #{self}.decipher(
              value: 'required - RSA ciphertext bytes, or an OpenSSL EC/X25519 peer public key or its raw point bytes',
              connection: connection, pin: pin, confirm: true
            )
            Decrypt through the same native decipher implementation.
            #{self}.decrypt(value: value, connection: connection, pin: pin, confirm: true)
            Verify a PIN once without guessing credentials or retrying a failure.
            #{self}.verify_pin(
              mode: 'optional - :signature for PW1/81, :extended for PW1/82, or :admin for PW3/83',
              connection: connection, pin: pin, confirm: true
            )
            Clear the selected PIN verification state on firmware 5.6 or newer.
            #{self}.unverify_pin(mode: :signature, connection: connection, confirm: true)
            Show module author information.
            #{self}.authors

            RSA signatures are raw modulus-length bytes; ECDSA signatures are ASN.1 DER;
            Ed25519 signatures are raw 64 bytes. ECDH returns a raw shared secret, not a
            decrypted OpenPGP message. No keyring, OpenPGP packet codec or trust verification
            is implied. Attestation returns a parsed certificate, not a validated trust chain.
            Unsupported firmware, curves, policies and advertised capabilities fail explicitly.
            Readback mismatches and timeouts never cause mutation replay.
          HELP
        end
      end
    end
  end
end
