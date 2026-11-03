# frozen_string_literal: true

require 'openssl'
require 'securerandom'

module PWN
  module Plugins
    module YubiKey
      # Native YubiHSM Auth APDUs. Protocol reference: yubikey-manager 5.9.1
      # yubikit/hsmauth.py and ykman/_cli/hsmauth.py. Independent Ruby encoding.
      module HSMAuth
        AID = ['a000000527210701'].pack('H*').freeze
        ALGORITHMS = { symmetric: 0x26, asymmetric: 0x27 }.freeze

        # Retain the device's ephemeral state; do not reselect another application.
        class Session
          def initialize(connection, timeout)
            raise ArgumentError, 'HSM Auth requires an APDU connection' unless connection.respond_to?(:exchange) && connection.respond_to?(:descriptor) && connection.descriptor[:protocol] == :apdu
            raise ArgumentError, 'timeout must be finite and positive' unless timeout.is_a?(Numeric) && timeout.finite? && timeout.positive?

            selected = Protocol.select(connection: connection, aid: AID, timeout: timeout)
            version = Protocol.tlv_map(data: selected)[0x79]
            raise ResponseError, 'Malformed HSM Auth SELECT version' unless version&.bytesize == 3

            @state = { connection: connection, timeout: timeout, version: version.bytes.freeze }.freeze
          end

          def [](key)
            @state.fetch(key)
          end
        end

        public_class_method def self.open_session(opts = {})
          Session.new(opts[:connection], opts.fetch(:timeout, 30))
        end

        public_class_method def self.execute(opts = {})
          args = opts.fetch(:args, [])
          raise ArgumentError, 'args must be an Array of Strings' unless args.is_a?(Array) && args.all?(String)
          return { application: :hsmauth, operations: operations } if args.empty? || [%w[credentials], %w[access]].include?(args)

          size = %w[credentials access].include?(args.first) ? 2 : 1
          operation = args.first(size).join(' ')
          raise ArgumentError, 'Unknown HSM Auth operation' unless operations.include?(operation)

          flags = case operation
                  when 'credentials symmetric' then %w[--touch --generate]
                  when 'credentials generate', 'credentials derive', 'credentials import' then %w[--touch]
                  when 'reset', 'credentials delete' then %w[--force]
                  when 'access change-management-key' then %w[--generate]
                  else []
                  end
          parsed = Protocol.parse_args(args: args.drop(size), flags: flags, values: operation == 'credentials export' ? %w[--format] : [])
          positional = parsed[:positionals]
          count = operation.start_with?('credentials ') && operation != 'credentials list' ? 1 : 0
          raise ArgumentError, 'Unexpected HSM Auth positional arguments' unless positional.length == count

          options = opts.merge(parsed[:options]).merge(label: positional.first, operation: operation)
          %i[generate touch force].each do |control|
            raise ArgumentError, "#{control} must be a boolean" if options.key?(control) && ![true, false].include?(options[control])
          end
          return list(session: session(options)) if operation == 'credentials list'
          return put(options) if ['credentials symmetric', 'credentials derive', 'credentials generate', 'credentials import'].include?(operation)
          return delete(options) if operation == 'credentials delete'
          return export(options) if operation == 'credentials export'
          return change_password(options) if operation == 'credentials change-password'
          return change_management(options) if operation.start_with?('access ')
          return reset(options) if operation == 'reset'

          session = session(options)
          { version: session[:version], management_key_retries: retries(session: session) }
        end

        public_class_method def self.operations
          ['info', 'reset', 'credentials list', 'credentials symmetric', 'credentials derive', 'credentials delete',
           'credentials generate', 'credentials import', 'credentials export', 'credentials change-password',
           'access change-management-key', 'access change-management-password']
        end

        public_class_method def self.calculate(opts = {})
          label = label(value: opts[:label])
          algorithm = opts.fetch(:algorithm, :symmetric)
          raise ArgumentError, 'algorithm must be :symmetric or :asymmetric' unless ALGORITHMS.key?(algorithm)

          context = bytes(value: opts[:context], size: algorithm == :symmetric ? 16 : 130)
          crypto = opts[:card_crypto]
          if algorithm == :asymmetric
            public_key = public_point(value: opts[:public_key])
            public_point(value: context.byteslice(0, 65))
            public_point(value: context.byteslice(65, 65))
            bytes(value: crypto, size: 16)
          else
            bytes(value: crypto, size: 8) if crypto
            raise ArgumentError, 'public_key is only valid for asymmetric credentials' if opts[:public_key]
          end
          Protocol.require_confirm(opts)
          password = password(opts.merge(name: :credential_password))
          session = session(opts)
          require_version(session: session, minimum: [5, 6, 0]) if algorithm == :asymmetric
          payload = tlv(tag: 0x71, value: label) + tlv(tag: 0x77, value: context)
          payload += tlv(tag: 0x7c, value: public_key) if public_key
          payload += tlv(tag: 0x78, value: crypto) if crypto
          payload += tlv(tag: 0x73, value: password)
          response = send_apdu(session: session, ins: 3, data: payload)
          raise ResponseError, 'HSM Auth must return exactly three 16-byte session keys' unless response.bytesize == 48

          { key_senc: response.byteslice(0, 16), key_smac: response.byteslice(16, 16), key_srmac: response.byteslice(32, 16) }
        end

        private_class_method def self.session(opts = {})
          supplied = opts[:session]
          return open_session(opts) if supplied.nil?
          raise ArgumentError, 'session must be an HSMAuth.open_session handle' unless supplied.is_a?(Session)
          raise ArgumentError, 'connection differs from supplied session' if opts[:connection] && !supplied[:connection].equal?(opts[:connection])

          supplied
        end

        public_class_method def self.challenge(opts = {})
          label = label(value: opts[:label])
          algorithm = opts.fetch(:algorithm, :symmetric)
          raise ArgumentError, 'algorithm must be :symmetric or :asymmetric' unless ALGORITHMS.key?(algorithm)

          Protocol.require_confirm(opts)
          password = password(opts.merge(name: :credential_password)) if algorithm == :asymmetric || opts.key?(:credential_password)
          session = session(opts)
          require_version(session: session, minimum: [5, 6, 0])
          payload = tlv(tag: 0x71, value: label)
          payload += tlv(tag: 0x73, value: password) if password && Protocol.version_at_least?(version: session[:version], minimum: [5, 7, 1])
          response = send_apdu(session: session, ins: 4, data: payload)
          if algorithm == :asymmetric
            public_point(value: response)
          else
            raise ResponseError, 'Malformed HSM Auth host challenge' unless response.bytesize == 8

            response
          end
        end

        private_class_method def self.require_version(opts = {})
          raise Error, 'HSM Auth operation is unsupported by the selected application version' unless Protocol.version_at_least?(version: opts.fetch(:session)[:version], minimum: opts.fetch(:minimum))
        end

        private_class_method def self.public_point(opts = {})
          value = opts[:value]
          if value.is_a?(OpenSSL::PKey::EC)
            raise ArgumentError, 'Only P-256 public keys are supported' unless value.group.curve_name == 'prime256v1'

            value = value.public_key.to_octet_string(:uncompressed)
          end
          bytes(value: value, size: 65)
          raise ArgumentError, 'Expected an uncompressed P-256 point' unless value.getbyte(0) == 4

          group = OpenSSL::PKey::EC::Group.new('prime256v1')
          point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new(value, 2))
          raise ArgumentError, 'Invalid P-256 public key' unless point.on_curve? && !point.infinity?

          value.b
        rescue OpenSSL::OpenSSLError
          raise ArgumentError, 'Invalid P-256 public key', cause: nil
        end

        private_class_method def self.private_scalar(opts = {})
          value = opts[:private_key]
          value = Protocol.secret(secret_provider: opts[:secret_provider], name: :private_key) if value.nil?
          if value.is_a?(String) && value.bytesize == 32
            scalar = value.b
          else
            if value.is_a?(String)
              raise ArgumentError, 'Private key input is too large' if value.bytesize > 65_536

              key_password = opts[:key_password]
              key_password = Protocol.secret(secret_provider: opts[:secret_provider], name: :key_password) if value.include?('ENCRYPTED') && key_password.nil?
              value = OpenSSL::PKey.read(value, key_password || '')
            end
            raise ArgumentError, 'Expected a private P-256 key' unless value.is_a?(OpenSSL::PKey::EC) && value.private? && value.group.curve_name == 'prime256v1'

            scalar = value.private_key.to_s(2).rjust(32, "\x00")
          end
          number = OpenSSL::BN.new(scalar, 2)
          order = OpenSSL::PKey::EC::Group.new('prime256v1').order
          raise ArgumentError, 'Invalid P-256 private scalar' unless number.to_i.positive? && number < order

          scalar
        rescue OpenSSL::OpenSSLError
          raise ArgumentError, 'Invalid or encrypted private key; supply the correct key_password once', cause: nil
        end

        private_class_method def self.export(opts = {})
          label = label(value: opts[:label])
          format = opts.fetch(:format, 'PEM').to_s.upcase
          raise ArgumentError, 'format must be RAW, PEM or DER' unless %w[RAW PEM DER].include?(format)

          session = session(opts)
          require_version(session: session, minimum: [5, 6, 0])
          point = public_point(value: send_apdu(session: session, ins: 10, data: tlv(tag: 0x71, value: label)))
          return point if format == 'RAW'

          algorithm = OpenSSL::ASN1::Sequence.new([OpenSSL::ASN1::ObjectId.new('id-ecPublicKey'), OpenSSL::ASN1::ObjectId.new('prime256v1')])
          der = OpenSSL::ASN1::Sequence.new([algorithm, OpenSSL::ASN1::BitString.new(point)]).to_der
          format == 'DER' ? der : OpenSSL::PKey.read(der).public_to_pem
        end

        private_class_method def self.change_password(opts = {})
          label = label(value: opts[:label])
          admin = opts.key?(:management_key) || opts.key?(:management_password) || opts[:auth_method] == :management
          raise ArgumentError, 'Management credential conflicts with explicit credential auth_method' if admin && opts[:auth_method] == :credential
          raise ArgumentError, 'Cannot combine credential and management authentication' if admin && opts.key?(:credential_password)
          raise ArgumentError, 'auth_method must be :management or :credential' if opts[:auth_method] && !%i[management credential].include?(opts[:auth_method])

          Protocol.require_confirm(opts)
          new_password = password(opts.merge(name: :new_credential_password))
          auth = admin ? management_key(opts) : password(opts.merge(name: :credential_password))
          session = session(opts)
          require_version(session: session, minimum: [5, 8, 0])
          payload = tlv(tag: 0x71, value: label) + tlv(tag: admin ? 0x7b : 0x73, value: auth) + tlv(tag: 0x73, value: new_password)
          send_apdu(session: session, ins: 11, p1: admin ? 1 : 0, data: payload)
          { status: :acknowledged, verification: :not_readable }
        end

        private_class_method def self.change_management(opts = {})
          raise ArgumentError, 'generate conflicts with supplied new management key' if opts[:generate] && (opts[:new_management_key] || opts[:new_management_password])
          raise ArgumentError, 'Specify only one new management credential' if opts.key?(:new_management_key) && opts.key?(:new_management_password)

          Protocol.require_confirm(opts)
          new_key = if opts[:generate]
                      SecureRandom.random_bytes(16)
                    elsif opts[:operation] == 'access change-management-password'
                      password(opts.merge(name: :new_management_password))
                    else
                      bytes(value: Protocol.secret(value: opts[:new_management_key], secret_provider: opts[:secret_provider], name: :new_management_key), size: 16)
                    end
          current = management_key(opts)
          session = session(opts)
          raise Error, 'Random management key generation is unsupported on HSM Auth 5.8 and later' if opts[:generate] && Protocol.version_at_least?(version: session[:version], minimum: [5, 8, 0])

          send_apdu(session: session, ins: 8, data: tlv(tag: 0x7b, value: current) + tlv(tag: 0x7b, value: new_key))
          result = { status: :acknowledged, verification: :not_readable }
          result[:generated_management_key] = new_key if opts[:generate]
          result
        end

        private_class_method def self.retries(opts = {})
          value = send_apdu(session: opts.fetch(:session), ins: 9)
          raise ResponseError, 'Malformed HSM Auth management retry counter' unless value.bytesize == 1 && value.getbyte(0) <= 8

          value.getbyte(0)
        end

        private_class_method def self.reset(opts = {})
          Protocol.require_confirm(opts)
          selected = session(opts)
          send_apdu(session: selected, ins: 6, p1: 0xde, p2: 0xad)
          fresh = open_session(connection: selected[:connection], timeout: selected[:timeout])
          raise ResponseError, 'HSM Auth reset readback failed' unless list(session: fresh).empty? && retries(session: fresh) == 8

          { reset: true, verified: true, verification: :empty_inventory_and_retries }
        end

        private_class_method def self.send_apdu(opts = {})
          session = opts.fetch(:session)
          Protocol.apdu(connection: session[:connection], timeout: session[:timeout], ins: opts.fetch(:ins), p1: opts.fetch(:p1, 0), p2: opts.fetch(:p2, 0), data: opts.fetch(:data, ''.b))
        end

        private_class_method def self.tlv(opts = {})
          Protocol.tlv(tag: opts.fetch(:tag), value: opts.fetch(:value))
        end

        private_class_method def self.label(opts = {})
          value = opts[:value]
          raise ArgumentError, 'label must contain 1 to 64 exact bytes' unless value.is_a?(String) && value.bytesize.between?(1, 64)

          value.b
        end

        private_class_method def self.bytes(opts = {})
          value = opts[:value]
          raise ArgumentError, "Expected exactly #{opts[:size]} raw bytes" unless value.is_a?(String) && value.bytesize == opts[:size]

          value.b
        end

        private_class_method def self.password(opts = {})
          name = opts.fetch(:name)
          value = opts[name]
          value = Protocol.secret(secret_provider: opts[:secret_provider], name: name) if value.nil?
          raise ArgumentError, 'HSM Auth password must be a String of at most 16 bytes' unless value.is_a?(String) && value.bytesize <= 16

          value.b.ljust(16, "\x00")
        end

        private_class_method def self.management_key(opts = {})
          raise ArgumentError, 'Choose management_key or management_password, not both' if opts.key?(:management_key) && opts.key?(:management_password)
          return password(opts.merge(name: :management_password)) if opts.key?(:management_password)

          value = Protocol.secret(value: opts[:management_key], secret_provider: opts[:secret_provider], name: :management_key)
          bytes(value: value, size: 16)
        end

        private_class_method def self.list(opts = {})
          result = Protocol.untlv(data: send_apdu(session: opts.fetch(:session), ins: 5)).map do |entry|
            value = entry[:value]
            raise ResponseError, 'Malformed HSM Auth LIST entry' unless entry[:tag] == 0x72 && value.bytesize.between?(4, 67) && [0, 1].include?(value.getbyte(1)) && value.getbyte(-1) <= 8

            algorithm = ALGORITHMS.key(value.getbyte(0))
            raise ResponseError, 'Unsupported HSM Auth credential algorithm' unless algorithm

            { label: value.byteslice(2, value.bytesize - 3), algorithm: algorithm, touch: value.getbyte(1) == 1, retries: value.getbyte(-1) }
          end
          raise ResponseError, 'Duplicate HSM Auth labels' unless result.map { |entry| entry[:label] }.uniq.length == result.length

          result
        end

        private_class_method def self.put(opts = {})
          label = label(value: opts[:label])
          touch = opts.fetch(:touch, false)
          raise ArgumentError, 'touch must be a boolean' unless [true, false].include?(touch)
          raise ArgumentError, 'generate conflicts with explicit key material' if opts[:generate] && (opts[:key_enc] || opts[:key_mac])

          Protocol.require_confirm(opts)
          asymmetric = ['credentials generate', 'credentials import'].include?(opts[:operation])
          if asymmetric
            scalar = opts[:operation] == 'credentials generate' ? ''.b : private_scalar(opts)
          elsif opts[:operation] == 'credentials derive'
            value = Protocol.secret(value: opts[:derivation_password], secret_provider: opts[:secret_provider], name: :derivation_password)
            key = OpenSSL::PKCS5.pbkdf2_hmac(value, 'Yubico', 10_000, 32, 'SHA256')
            key_enc = key.byteslice(0, 16)
            key_mac = key.byteslice(16, 16)
          elsif opts[:generate]
            key_enc = SecureRandom.random_bytes(16)
            key_mac = SecureRandom.random_bytes(16)
          else
            key_enc = bytes(value: Protocol.secret(value: opts[:key_enc], secret_provider: opts[:secret_provider], name: :key_enc), size: 16)
            key_mac = bytes(value: Protocol.secret(value: opts[:key_mac], secret_provider: opts[:secret_provider], name: :key_mac), size: 16)
          end
          password = password(opts.merge(name: :credential_password))
          management = management_key(opts)
          session = session(opts)
          require_version(session: session, minimum: [5, 6, 0]) if asymmetric
          raise ArgumentError, 'HSM Auth label already exists; delete explicitly before replacing it' if list(session: session).any? { |entry| entry[:label] == label }

          algorithm = asymmetric ? :asymmetric : :symmetric
          payload = tlv(tag: 0x7b, value: management) + tlv(tag: 0x71, value: label) + tlv(tag: 0x74, value: [ALGORITHMS.fetch(algorithm)].pack('C'))
          payload += asymmetric ? tlv(tag: 0x7d, value: scalar) : tlv(tag: 0x75, value: key_enc) + tlv(tag: 0x76, value: key_mac)
          payload += tlv(tag: 0x73, value: password) + tlv(tag: 0x7a, value: [touch ? 1 : 0].pack('C'))
          send_apdu(session: session, ins: 1, data: payload)
          result = list(session: session).find { |entry| entry[:label] == label }
          raise ResponseError, 'HSM Auth import readback did not match metadata' unless result && result[:algorithm] == algorithm && result[:touch] == touch

          result = result.merge(verified: true, verification: :metadata_only)
          result[:generated_keys] = { key_enc: key_enc, key_mac: key_mac } if opts[:generate]
          result
        end

        private_class_method def self.delete(opts = {})
          label = label(value: opts[:label])
          Protocol.require_confirm(opts)
          management = management_key(opts)
          session = session(opts)
          raise ResponseError, 'No exact HSM Auth credential label' unless list(session: session).any? { |entry| entry[:label] == label }

          send_apdu(session: session, ins: 2, data: tlv(tag: 0x7b, value: management) + tlv(tag: 0x71, value: label))
          raise ResponseError, 'HSM Auth delete readback failed' if list(session: session).any? { |entry| entry[:label] == label }

          { deleted: label, verified: true }
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~HELP
            Execute native credential management without a subprocess.
            #{self}.execute(
              args: 'optional - operation argv after hsmauth; empty returns local metadata',
              connection: 'required - selected APDU connection except local help',
              session: 'optional - existing open_session handle instead of reselecting connection',
              confirm: 'required - literal true for mutations and authentication',
              credential_password: 'optional - current in-memory password up to sixteen bytes; explicit empty is allowed',
              new_credential_password: 'optional - new in-memory credential password up to sixteen bytes',
              management_key: 'optional - exactly sixteen raw authorization key bytes, never guessed',
              management_password: 'optional - at most sixteen password bytes instead of management_key',
              new_management_key: 'optional - exactly sixteen raw bytes for change-management-key',
              new_management_password: 'optional - at most sixteen password bytes for change-management-password',
              key_enc: 'optional - sixteen raw AES encryption key bytes for symmetric import',
              key_mac: 'optional - sixteen raw AES authentication key bytes for symmetric import',
              derivation_password: 'optional - in-memory password for PBKDF2 symmetric derivation',
              private_key: 'optional - raw thirty-two byte P-256 scalar, PEM/DER String or private OpenSSL EC object',
              key_password: 'optional - in-memory PEM/DER decryption password; never retried',
              auth_method: 'optional - credential or management Symbol for password-change authorization',
              generate: 'optional - boolean symmetric key generation or pre-5.8 management-key generation',
              touch: 'optional - boolean touch requirement on credential creation',
              format: 'optional - RAW point, PEM or DER for public-key export, returned in memory',
              secret_provider: 'optional - callable receiving a missing secret field Symbol after consent',
              timeout: 'optional - finite positive I/O timeout seconds'
            )
            Enumerate implemented operation leaves only.
            #{self}.operations
            Select the application once for a multi-command cryptographic session.
            #{self}.open_session(
              connection: 'required - caller-owned raw APDU transport handle',
              timeout: 'optional - finite positive I/O timeout seconds'
            )
            Obtain a host challenge without losing ephemeral session state.
            #{self}.challenge(
              session: 'required - open_session handle shared with the following calculate call',
              label: 'required - full exact credential label bytes',
              algorithm: 'optional - symmetric or asymmetric Symbol, default symmetric',
              credential_password: 'optional - in-memory credential password; required for asymmetric mode',
              confirm: 'required - literal true for challenge generation or authentication'
            )
            Calculate three in-memory session keys using one credential.
            #{self}.calculate(
              connection: 'optional - raw APDU handle when no existing session is supplied',
              session: 'optional - shared open_session handle retaining an earlier challenge',
              label: 'required - full exact credential label bytes',
              algorithm: 'optional - symmetric or asymmetric Symbol, default symmetric',
              context: 'required - sixteen symmetric challenge bytes or two uncompressed P-256 points (130 bytes)',
              public_key: 'optional - required asymmetric HSM public key, raw 65-byte point or OpenSSL EC object',
              card_crypto: 'optional - eight-byte symmetric or required sixteen-byte asymmetric card cryptogram',
              credential_password: 'required - in-memory password, at most sixteen raw bytes',
              confirm: 'required - literal true for one authentication attempt',
              timeout: 'optional - finite positive I/O timeout seconds'
            )
            Import/export use data in memory, not filenames. No credential or default key is guessed.
            Reuse the same session between challenge and calculate; do not reselect another application.
            Creation/deletion read back metadata. Password/key changes return acknowledged/not_readable;
            they do not perform a second authentication attempt to pretend secret contents were read back.
            Asymmetric operations require 5.6; credential-password changes require 5.8.
            Display module author information.
            #{self}.authors
          HELP
        end
      end
    end
  end
end
