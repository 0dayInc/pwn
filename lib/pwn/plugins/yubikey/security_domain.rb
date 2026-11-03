# frozen_string_literal: true

require 'openssl'
require_relative 'protocol'
require_relative 'security_domain/scp'

module PWN
  module Plugins
    module YubiKey
      # Native Security Domain administration. Reference: Yubico yubikit 5.9.1
      # securitydomain.py; GlobalPlatform Card Specification 2.3, Amendments D/F.
      module SecurityDomain
        AID = ['a000000151000000'].pack('H*').freeze
        OPERATIONS = ['info', 'reset', 'keys generate', 'keys import', 'keys export', 'keys delete', 'keys set-allowlist', 'keys set-certificate', 'keys set-ca-issuer'].freeze
        SCP11_KIDS = [0x11, 0x13, 0x15].freeze
        CA_KIDS = [0x10, *(0x20..0x2f)].freeze
        CURVES = { 'prime256v1' => 0, 'secp384r1' => 1, 'secp521r1' => 2, 'brainpoolP256r1' => 3, 'brainpoolP384r1' => 5, 'brainpoolP512r1' => 7 }.freeze

        # Parse nonsecret argv before selecting or authenticating a device.
        class Request # rubocop:disable Metrics/ClassLength
          def initialize(opts)
            @opts = opts
            @crypto = SCP::Crypto.new
            parsed = Protocol.parse_args(args: opts.fetch(:args, []), flags: ['--force'], values: ['--replace-kvn'])
            words = parsed[:positionals]
            @operation = words.shift
            @operation += " #{words.shift}" if @operation == 'keys'
            raise ArgumentError, 'Unknown Security Domain operation' unless OPERATIONS.include?(@operation)

            options = parsed[:options]
            @params = {}
            if %w[info reset].include?(@operation)
              raise ArgumentError, 'Operation takes no positional arguments' unless words.empty?
              raise ArgumentError, 'Unsupported option for operation' unless (options.keys - (@operation == 'reset' ? [:force] : [])).empty?
            else
              raise ArgumentError, 'Expected KID and KVN' if words.length < 2

              @params = { kid: integer(words.shift), kvn: integer(words.shift) }
              @params[:replace_kvn] = integer(options.fetch(:replace_kvn, opts.fetch(:replace_kvn, 0)))
              allowed = if ['keys generate', 'keys import'].include?(@operation)
                          [:replace_kvn]
                        else
                          (@operation == 'keys delete' ? [:force] : [])
                        end
              raise ArgumentError, 'Unsupported option for operation' unless (options.keys - allowed).empty?
              raise ArgumentError, 'Replacement KVN must be in 0..127' unless @params[:replace_kvn].between?(0, 127)

              # Binary export/generation returns data; '-' is an optional stdout
              # compatibility marker, never an instruction to write a file.
              words.pop if ['keys generate', 'keys export'].include?(@operation) && words == ['-']
              if @operation == 'keys set-allowlist'
                values = opts.fetch(:serials, words)
                raise ArgumentError, 'Serials must be a bounded Array' unless values.is_a?(Array) && values.length <= 256

                @params[:serials] = values.map { |value| integer(value, maximum: (1 << 160) - 1) }
                words = []
              end
              raise ArgumentError, 'Unexpected positional argument; supply keys/certificates in memory' unless words.empty?

              validate_reference
            end
            validate_consent
            prepare_material
          end

          def execute
            session = Session.new(@opts)
            case @operation
            when 'info' then session.info
            when 'reset' then session.reset
            when 'keys generate' then session.generate(@params)
            when 'keys import'
              result = session.import_key(@params)
              session.store_certificates(@params) if @params[:certificates]
              session.store_ca(@params) if @params[:ski]
              result
            when 'keys export' then session.export(@params)
            when 'keys delete' then session.delete(@params)
            when 'keys set-allowlist' then session.allowlist(@params)
            when 'keys set-certificate' then session.store_certificates(@params)
            when 'keys set-ca-issuer' then session.store_ca(@params)
            end
          end

          private

          def validate_reference
            kid = @params[:kid]
            kvn = @params[:kvn]
            case @operation
            when 'keys delete'
              raise ArgumentError, 'Deleting all keys requires reset, not wildcard deletion' if kid.zero? && kvn.zero?
              raise ArgumentError, 'Invalid key identifier' unless [0, 1, 2, 3, *SCP11_KIDS, *CA_KIDS].include?(kid)
              raise ArgumentError, 'SCP03 keys must be deleted by a nonzero KVN' if [1, 2, 3].include?(kid) && kvn.zero?
            when 'keys import'
              raise ArgumentError, 'Invalid import KID' unless [1, *SCP11_KIDS, *CA_KIDS].include?(kid)
              raise ArgumentError, 'Import KVN must be in 1..127' unless kvn.between?(1, 127)
            when 'keys generate'
              raise ArgumentError, 'Generation requires SCP11 KID and KVN in 1..127' unless SCP11_KIDS.include?(kid) && kvn.between?(1, 127)
            when 'keys set-allowlist'
              raise ArgumentError, 'Allowlist requires an OCE CA key reference' unless CA_KIDS.include?(kid) && kvn.positive?
            else
              raise ArgumentError, 'Invalid SCP11/CA key reference' unless [*SCP11_KIDS, *CA_KIDS].include?(kid) && kvn.positive?
            end
          end

          def validate_consent
            return if ['info', 'keys export'].include?(@operation)

            raise ConfirmationRequired, 'Security Domain mutation requires confirm: true' unless @opts[:confirm] == true

            connection = @opts[:connection]
            if @operation == 'reset'
              raise ArgumentError, 'Reset requires a plain connection without an active secure channel' if connection.is_a?(SCP::Connection) || connection&.descriptor&.dig(:secure_channel)
            else
              raise SCP::ChannelError, 'SCP03 or SCP11a administration required' unless connection.is_a?(SCP::Connection) && connection.authenticated?
            end
          end

          def prepare_material
            case @operation
            when 'keys generate'
              @params[:curve] = @opts.fetch(:curve, 'prime256v1')
              raise ArgumentError, 'Unsupported EC curve' unless CURVES.key?(@params[:curve])
            when 'keys import'
              prepare_import
            when 'keys set-certificate'
              @params[:certificates] = @crypto.certificates(@opts.fetch(:certificates))
              @crypto.validate_chain(@params[:certificates])
              raise ArgumentError, 'Certificate bundle too large' if @params[:certificates].sum { |cert| cert.to_der.bytesize } > 60_000
            when 'keys set-ca-issuer'
              @params[:ski] = @opts[:ski]
              raise ArgumentError, 'SKI must be a nonempty binary String of at most 64 bytes' unless @params[:ski].is_a?(String) && @params[:ski].bytesize.between?(1, 64)
            end
          end

          def prepare_import
            if @params[:kid] == 1
              @params[:keys] = %i[key_enc key_mac key_dek].map do |name|
                value = @opts[name]
                value = @opts[:secret_provider].call(name) if value.nil? && @opts[:secret_provider].respond_to?(:call)
                raise ArgumentError, 'Import requires three explicit 16-byte AES keys' unless value.is_a?(String) && value.bytesize == 16

                value.b.dup
              end
              return
            end
            private_key = SCP11_KIDS.include?(@params[:kid])
            value = @opts[:key]
            if @opts[:certificate]
              raise ArgumentError, 'CA certificate input cannot be combined with a key or private-key KID' if value || private_key

              cert = @crypto.certificates([@opts[:certificate]]).first
              constraints = cert.extensions.find { |ext| ext.oid == 'basicConstraints' }
              usage = cert.extensions.find { |ext| ext.oid == 'keyUsage' }
              raise ArgumentError, 'CA certificate requires CA:true and keyCertSign usage' unless constraints&.value&.include?('CA:TRUE') && usage&.value&.include?('Certificate Sign')
              raise ArgumentError, 'CA certificate validity check failed' unless Time.now.between?(cert.not_before, cert.not_after)

              value = cert.public_key
              ski = cert.extensions.find { |ext| ext.oid == 'subjectKeyIdentifier' }
              @params[:ski] = [ski.value.delete(':')].pack('H*') if ski
            end
            value = @opts[:secret_provider].call(:key) if value.nil? && @opts[:secret_provider].respond_to?(:call)
            @params[:key] = @crypto.ec_key(value, private_key: private_key)
            raise ArgumentError, 'CA imports must contain a public key, not private material' if !private_key && @params[:key].private?

            @params[:curve] = @params[:key].group.curve_name
            raise ArgumentError, 'Unsupported EC curve' unless CURVES.key?(@params[:curve])
            raise ArgumentError, 'Non-block-aligned EC private scalars are unsupported by the YubiKey PUT KEY format' if private_key && (((@params[:key].group.degree + 7) / 8) % 16).nonzero?

            if @opts[:certificates]
              raise ArgumentError, 'Certificate bundles accompany SCP11 private keys only' unless private_key

              @params[:certificates] = @crypto.certificates(@opts[:certificates])
              leaf = @crypto.validate_chain(@params[:certificates])
              raise ArgumentError, 'Imported key does not match certificate' unless @crypto.equal?(leaf.public_to_der, @params[:key].public_to_der)
              raise ArgumentError, 'Certificate bundle too large' if @params[:certificates].sum { |cert| cert.to_der.bytesize } > 60_000
            end
            @params[:ski] = @opts[:ski] if @opts.key?(:ski)
            return unless @params[:ski] && (!@params[:ski].is_a?(String) || !@params[:ski].bytesize.between?(1, 64))

            raise ArgumentError, 'SKI must be a nonempty binary String of at most 64 bytes'
          end

          def integer(value, maximum: 255)
            return value if value.is_a?(Integer) && value.between?(0, maximum)
            raise ArgumentError, 'Expected exact unsigned decimal or 0x-hex integer' unless value.is_a?(String) && value.match?(/\A(?:0x[0-9a-fA-F]+|[0-9]+)\z/)

            number = Integer(value, value.start_with?('0x') ? 16 : 10)
            raise ArgumentError, 'Integer outside permitted range' unless number.between?(0, maximum)

            number
          end
        end

        # Native administrative wire commands, after Request validation.
        class Session # rubocop:disable Metrics/ClassLength
          def initialize(opts)
            @connection = opts.fetch(:connection)
            @timeout = opts.fetch(:timeout, 30)
            raise ArgumentError, 'An APDU connection is required' unless @connection.descriptor[:protocol] == :apdu
            raise ArgumentError, 'Timeout must be finite and positive' unless @timeout.is_a?(Numeric) && @timeout.finite? && @timeout.positive?

            Protocol.select(connection: @connection, aid: AID, timeout: @timeout) unless @connection.is_a?(SCP::Connection)
          end

          def info
            keys = key_information
            recognition = Protocol.untlv(data: get(0x66))
            raise ResponseError, 'Invalid card recognition data' unless recognition.length == 1 && recognition.first[:tag] == 0x73

            { keys: keys, card_recognition_data: recognition.first[:value], ca_identifiers: ca_identifiers }
          end

          def key_information
            keys = Protocol.untlv(data: get(0xe0)).map do |row|
              value = row[:value]
              raise ResponseError, 'Invalid key-information template' unless row[:tag] == 0xc0 && value.bytesize >= 4 && value.bytesize.even?

              pairs = value.byteslice(2..).bytes.each_slice(2).to_a
              raise ResponseError, 'Duplicate key type in key-information template' unless pairs.map(&:first).uniq.length == pairs.length

              { kid: value.getbyte(0), kvn: value.getbyte(1), types: pairs.to_h }
            end
            raise ResponseError, 'Duplicate key reference' unless keys.map { |key| [key[:kid], key[:kvn]] }.uniq.length == keys.length

            keys
          end

          def ca_identifiers
            [[0xff33, :kloc], [0xff34, :klcc]].flat_map do |tag, kind|
              begin
                rows = Protocol.untlv(data: get(tag))
              rescue Protocol::APDUError => e
                raise unless e.status == 0x6a88

                next []
              end
              raise ResponseError, 'Invalid CA identifier sequence' unless rows.length.even?

              rows.each_slice(2).map do |ski, ref|
                raise ResponseError, 'Invalid CA identifier record' unless ski[:tag] == 0x42 && ref[:tag] == 0x83 && ref[:value].bytesize == 2 && !ski[:value].empty?

                { kid: ref[:value].getbyte(0), kvn: ref[:value].getbyte(1), ski: ski[:value], kind: kind }
              end
            end
          end

          def import_key(params)
            crypto = SCP::Crypto.new
            data = [params[:kvn]].pack('C')
            expected = data.dup
            p2 = params[:kid]
            if params[:keys]
              p2 |= 0x80
              params[:keys].each do |key|
                check = crypto.aes(key, "\1".b * 16, initialization_vector: "\0".b * 16).byteslice(0, 3)
                data += Protocol.tlv(tag: 0x88, value: @connection.wrap_key(key)) + "\3".b + check
                expected += check
              end
            else
              key = params[:key]
              if key.private?
                size = (key.group.degree + 7) / 8
                scalar = key.private_key.to_s(2).rjust(size, "\0".b)
                data += Protocol.tlv(tag: 0xb1, value: @connection.wrap_key(scalar))
              else
                data += Protocol.tlv(tag: 0xb0, value: key.public_key.to_octet_string(:uncompressed))
              end
              data += Protocol.tlv(tag: 0xf0, value: [CURVES.fetch(params[:curve])].pack('C')) + "\0".b
            end
            response = send_apdu(cla: 0x80, ins: 0xd8, p1: params[:replace_kvn], p2: p2, data: data)
            raise ResponseError, 'Imported key check value mismatch; do not retry an uncertain write' unless crypto.equal?(expected, response)

            { imported: true, kid: params[:kid], kvn: params[:kvn] }
          end

          def generate(params)
            data = [params[:kvn]].pack('C') + Protocol.tlv(tag: 0xf0, value: [CURVES.fetch(params[:curve])].pack('C'))
            response = Protocol.untlv(data: send_apdu(cla: 0x80, ins: 0xf1, p1: params[:replace_kvn], p2: params[:kid], data: data))
            raise ResponseError, 'Invalid generated public key response' unless response.length == 1 && response.first[:tag] == 0xb0

            SCP::Crypto.new.public_point(response.first[:value], params[:curve]).public_to_pem.b
          end

          def export(params)
            rows = Protocol.untlv(data: get(0xbf21, reference(params)))
            raise ResponseError, 'No certificate chain stored for key' if rows.empty?

            rows.reverse.map do |row|
              raise ResponseError, 'Invalid certificate bundle' unless row[:tag] == 0x30

              OpenSSL::X509::Certificate.new(Protocol.tlv(tag: 0x30, value: row[:value])).to_pem.b
            end.join.b
          rescue OpenSSL::OpenSSLError
            raise ResponseError, 'Invalid stored certificate encoding', cause: nil
          end

          def delete(params)
            kid = [1, 2, 3].include?(params[:kid]) ? 0 : params[:kid]
            data = kid.zero? ? ''.b : Protocol.tlv(tag: 0xd0, value: [kid].pack('C'))
            data += Protocol.tlv(tag: 0xd2, value: [params[:kvn]].pack('C')) unless params[:kvn].zero?
            send_apdu(cla: 0x80, ins: 0xe4, p1: 0, p2: 0, data: data)
            { deleted: true, kid: params[:kid], kvn: params[:kvn] }
          end

          def allowlist(params)
            serials = params[:serials].map do |serial|
              hex = serial.to_s(16)
              hex = "0#{hex}" if hex.length.odd?
              bytes = [hex].pack('H*')
              bytes = "\0".b + bytes if bytes.getbyte(0).anybits?(0x80)
              Protocol.tlv(tag: 0x93, value: bytes)
            end.join.b
            store(reference(params) + Protocol.tlv(tag: 0x70, value: serials))
          end

          def store_certificates(params)
            store(reference(params) + Protocol.tlv(tag: 0xbf21, value: params[:certificates].map(&:to_der).join.b))
          end

          def store_ca(params)
            role = SCP11_KIDS.include?(params[:kid]) ? 1 : 0
            store(Protocol.tlv(tag: 0xa6, value: Protocol.tlv(tag: 0x80, value: [role].pack('C')) + Protocol.tlv(tag: 0x42, value: params[:ski]) + Protocol.tlv(tag: 0x83, value: [params[:kid], params[:kvn]].pack('CC'))))
          end

          def reset
            keys = key_information
            raise ResponseError, 'Unknown key type; refusing incomplete reset' unless keys.all? { |key| [1, 2, 3, *SCP11_KIDS, *CA_KIDS].include?(key[:kid]) }

            keys.each do |key|
              kid = key[:kid]
              next if [2, 3].include?(kid)

              kvn = key[:kvn]
              ins = case kid
                    when 1
                      kid = kvn = 0
                      0x50
                    when 0x11, 0x15 then 0x82
                    when 0x13 then 0x88
                    else
                      raise ResponseError, 'Unknown key type; refusing incomplete reset' unless CA_KIDS.include?(kid)

                      0x2a
                    end
              blocked = false
              65.times do
                send_apdu(cla: 0x80, ins: ins, p1: kvn, p2: kid, data: "\0".b * 8)
              rescue Protocol::APDUError => e
                if [0x6983, 0x6982].include?(e.status)
                  blocked = true
                  break
                end
                raise unless e.status == 0x6a80
              end
              raise ResponseError, 'Reset retry bound reached; state uncertain, do not retry automatically' unless blocked
            end
            after = key_information
            default_present = after.any? { |key| key[:kid] == 1 && key[:kvn] == 0xff }
            default_only = after.all? { |key| key[:kid] == 0x13 || ([1, 2, 3].include?(key[:kid]) && key[:kvn] == 0xff) }
            raise ResponseError, 'Security Domain reset state could not be verified' unless default_present && default_only

            { reset: true, keys: after }
          end

          private

          def reference(params)
            Protocol.tlv(tag: 0xa6, value: Protocol.tlv(tag: 0x83, value: [params[:kid], params[:kvn]].pack('CC')))
          end

          def store(data)
            send_apdu(ins: 0xe2, p1: 0x90, p2: 0, data: data)
            { stored: true }
          end

          def get(tag, data = ''.b)
            send_apdu(ins: 0xca, p1: tag >> 8, p2: tag & 0xff, data: data)
          end

          def send_apdu(opts)
            Protocol.apdu(opts.merge(connection: @connection, timeout: @timeout, extended: true))
          end
        end

        private_constant :Request, :Session

        # Execute a native Security Domain management leaf operation.
        public_class_method def self.execute(opts = {})
          args = opts[:args] || []
          raise ArgumentError, 'args must be an Array of Strings' unless args.is_a?(Array) && args.all?(String)
          return { operations: operations } if args.empty? || args == ['keys']

          Request.new(opts).execute
        end

        # Authenticate an APDU transport with explicit, memory-only keys.
        public_class_method def self.secure_connection(opts = {})
          raise ArgumentError, 'connection is required' unless opts[:connection]

          SCP.open(opts)
        end

        # Enumerate implemented leaf operations without accessing a device.
        public_class_method def self.operations
          OPERATIONS.dup
        end

        # Return module attribution without device access.
        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Print callable API documentation without device access.
        public_class_method def self.help
          puts <<~HELP
            Execute a native Security Domain management operation.
            #{self}.execute(
              args: 'optional - leaf command Array; empty returns local metadata',
              connection: 'required - native APDU handle; SCP03/SCP11a wrapper for mutations except reset',
              timeout: 'optional - finite positive per-command seconds, default 30',
              confirm: 'optional - literal true required for mutations, including reset',
              key_enc: 'optional - required 16-byte new K-ENC for SCP03 import',
              key_mac: 'optional - required 16-byte new K-MAC for SCP03 import',
              key_dek: 'optional - required 16-byte new K-DEK for SCP03 import',
              key: 'optional - in-memory EC private key for SCP11 or public key for CA import; object/PEM/DER',
              certificate: 'optional - in-memory CA X509 object/PEM/DER instead of key for CA import',
              certificates: 'optional - leaf-last X509 bundle for set-certificate or private-key import',
              ski: 'optional - raw 1..64 byte issuer identifier for set-ca-issuer or import',
              curve: 'optional - OpenSSL named curve for generation; default prime256v1',
              replace_kvn: 'optional - integer 0..127 replacing an existing KVN; default 0 creates',
              serials: 'optional - Array of certificate serial integers for set-allowlist, instead of argv serials',
              secret_provider: 'optional - callable accepting a missing import field Symbol; invoked only after consent'
            )
            Authenticate a native APDU transport using explicit in-memory keys.
            #{self}.secure_connection(
              connection: 'required - plain native APDU transport; owned by returned wrapper',
              scp: 'required - Symbol scp03, scp11a, scp11b or scp11c',
              kvn: 'required - exact integer card key version 0..255; zero explicitly selects any version',
              kid: 'optional - exact integer KID; must match selected protocol',
              confirm: 'required - literal true permits authentication attempts',
              timeout: 'optional - finite positive handshake seconds, default 30',
              key_enc: 'optional - required 16-byte K-ENC binary String for SCP03',
              key_mac: 'optional - required 16-byte K-MAC binary String for SCP03',
              key_dek: 'optional - 16-byte SCP03 K-DEK, required to import secret keys',
              card_public_key: 'optional - SCP11 pinned EC public key object/PEM/DER; required unless CA anchors supplied',
              ca_certificates: 'optional - explicit trusted CA X509 object/PEM/DER Array for SCP11 card verification',
              card_certificates: 'optional - leaf-last card X509 bundle; otherwise fetched when CA anchors provided',
              oce_private_key: 'optional - required EC private key object/PEM/DER for SCP11a/c',
              oce_certificates: 'optional - required leaf-last OCE X509 bundle for SCP11a/c',
              oce_kid: 'optional - OCE CA KID integer 0, 16 or 32..47; default zero selects a matching CA',
              oce_kvn: 'optional - OCE CA key version integer 0..255; default zero selects any'
            )
            Enumerate implemented native leaf operations without device access.
            #{self}.operations
            Return module author information.
            #{self}.authors
          HELP
        end
      end
    end
  end
end
