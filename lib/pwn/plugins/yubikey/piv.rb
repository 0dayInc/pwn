# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'stringio'
require 'zlib'

module PWN
  module Plugins
    module YubiKey
      # Native PIV application. Wire reference: NIST SP 800-73 and Yubico
      # yubikey-manager 5.9.1, yubikit/piv.py and ykman/{piv,_cli/piv}.py.
      # Those sources are specifications only; no executable backend is used.
      module PIV
        AID = ['a000000308000010000100'].pack('H*').freeze

        MANAGEMENT = { 'TDES' => [3, 24, 'DES-EDE3-ECB'], 'AES128' => [8, 16, 'AES-128-ECB'], 'AES192' => [10, 24, 'AES-192-ECB'], 'AES256' => [12, 32, 'AES-256-ECB'] }.freeze
        GRAMMAR = {
          'info' => [0, [], []], 'reset' => [0, %w[force], []],
          'access change-pin' => [0, [], []], 'access change-puk' => [0, [], []],
          'access unblock-pin' => [0, [], []], 'access set-retries' => [2, %w[force], []],
          'access change-management-key' => [0, %w[touch protect generate force], %w[algorithm]],
          'objects import' => [2, [], []], 'objects export' => [2, [], []], 'objects generate' => [1, [], []],
          'keys generate' => [2, [], %w[algorithm format pin-policy touch-policy]],
          'keys import' => [2, [], %w[pin-policy touch-policy]], 'keys info' => [1, [], []],
          'keys export' => [2, %w[verify], %w[format]], 'keys attest' => [2, [], %w[format]],
          'keys move' => [2, [], []], 'keys delete' => [1, [], []],
          'certificates import' => [2, %w[verify compress update-chuid no-update-chuid], []],
          'certificates export' => [2, [], %w[format]],
          'certificates generate' => [1..2, %w[update-chuid no-update-chuid], %w[subject valid-days hash-algorithm]],
          'certificates request' => [3, [], %w[subject hash-algorithm]],
          'certificates delete' => [1, %w[update-chuid no-update-chuid], []]
        }.freeze

        ALGORITHMS = { 'RSA1024' => [6, 128], 'RSA2048' => [7, 256], 'RSA3072' => [5, 384], 'RSA4096' => [0x16, 512],
                       'ECCP256' => [0x11, 32], 'ECCP384' => [0x14, 48], 'ED25519' => [0xe0, 32], 'X25519' => [0xe1, 32] }.freeze
        PIN_POLICIES = { 'DEFAULT' => 0, 'NEVER' => 1, 'ONCE' => 2, 'ALWAYS' => 3, 'MATCH_ONCE' => 4, 'MATCH_ALWAYS' => 5 }.freeze
        TOUCH_POLICIES = { 'DEFAULT' => 0, 'NEVER' => 1, 'ALWAYS' => 2, 'CACHED' => 3 }.freeze
        SLOTS = { 'AUTHENTICATION' => 0x9a, 'SIGNATURE' => 0x9c, 'KEY_MANAGEMENT' => 0x9d, 'CARD_AUTH' => 0x9e, 'ATTESTATION' => 0xf9 }.merge((1..20).to_h { |n| ["RETIRED#{n}", 0x81 + n] }).freeze
        OBJECTS = { 'CCC' => 0x5fc107, 'CAPABILITY' => 0x5fc107, 'CHUID' => 0x5fc102, 'DISCOVERY' => 0x7e,
                    'AUTHENTICATION' => 0x5fc105, 'SIGNATURE' => 0x5fc10a, 'KEY_MANAGEMENT' => 0x5fc10b, 'CARD_AUTH' => 0x5fc101,
                    'FINGERPRINTS' => 0x5fc103, 'SECURITY' => 0x5fc106, 'FACIAL' => 0x5fc108, 'PRINTED' => 0x5fc109,
                    'KEY_HISTORY' => 0x5fc10c, 'IRIS' => 0x5fc121, 'ATTESTATION' => 0x5fff01, 'PIVMAN' => 0x5fff00 }.merge((1..20).to_h { |n| ["RETIRED#{n}", 0x5fc10c + n] }).freeze

        # Firmware does not support the requested operation.
        class UnsupportedError < Error; end

        # A failed reference verification; the secret is never included.
        class PinError < Error
          attr_reader :attempts_remaining

          def initialize(attempts_remaining)
            @attempts_remaining = attempts_remaining
            super("PIV verification failed; #{attempts_remaining} attempts remaining")
          end
        end

        # Execute a native PIV leaf with secrets passed only in memory.
        # @param opts [Hash] args and connection plus operation-specific options
        # @return [Hash, String] structured outcome or explicit binary export
        public_class_method def self.execute(opts = {})
          Session.new(opts).execute(opts[:args] || [])
        end

        # Authenticate both card and host with a fresh random challenge.
        # @param opts [Hash] connection, management_key and literal confirmation
        # @return [Symbol] :authenticated
        public_class_method def self.authenticate(opts = {})
          Session.new(opts).authenticate(opts[:management_key])
        end

        # Verify the caller's PIN without guessing or retrying credentials.
        # @param opts [Hash] native connection, pin, confirmation and timeout
        # @return [Symbol] :verified
        public_class_method def self.verify_pin(opts = {})
          Session.new(opts).verify_pin(opts[:pin])
        end

        # Sign a message with a non-exportable device private key.
        # @param opts [Hash] slot, algorithm, message, PIN and padding options
        # @return [String] raw signature
        public_class_method def self.sign(opts = {})
          Session.new(opts).sign(opts[:slot], opts[:message])
        end

        # Decrypt an RSA ciphertext on the device and unpad using OpenSSL.
        # @param opts [Hash] slot, ciphertext, PIN and OAEP or PKCS1 options
        # @return [String] binary plaintext
        public_class_method def self.decrypt(opts = {})
          Session.new(opts).decrypt(opts[:slot], opts[:ciphertext])
        end

        # Derive an ECDH or X25519 shared secret using the device key.
        # @param opts [Hash] slot, peer_public_key and authentication options
        # @return [String] binary shared secret
        public_class_method def self.calculate_secret(opts = {})
          Session.new(opts).calculate_secret(opts[:slot], opts[:peer_public_key])
        end

        # Verify a biometric and optionally obtain a session-local temporary PIN.
        # @param opts [Hash] connection, confirmation and temporary PIN request
        # @return [Symbol, String] verified status or temporary PIN bytes
        public_class_method def self.verify_uv(opts = {})
          Session.new(opts).verify_uv(request_pin: opts[:request_temporary_pin])
        end

        # Verify a session-local temporary PIN previously issued by the card.
        # @param opts [Hash] connection, confirmation and temporary_pin bytes
        # @return [Symbol] :verified
        public_class_method def self.verify_temporary_pin(opts = {})
          Session.new(opts).verify_temporary_pin(opts[:temporary_pin])
        end

        # List native leaf names without selecting a device.
        # @param opts [Hash] optional operation prefix
        # @return [Array<String>] implemented operations
        public_class_method def self.operations(opts = {})
          prefix = opts[:prefix].to_s
          GRAMMAR.keys.select { |name| name.start_with?(prefix) }
        end

        # Show native PIV usage and secret-handling boundaries.
        # @return [nil]
        public_class_method def self.help
          puts <<~HELP
            USAGE:
            # Execute a native PIV leaf; group paths return local help.
            #{self}.execute(
              args: 'required - family-relative Array of nonsecret arguments',
              connection: 'required - native APDU connection selected by the parent transport',
              confirm: 'optional - literal true required for authentication, writes and private-key use',
              pin: 'optional - current PIN in memory, never an argument token',
              puk: 'optional - current PUK in memory for change or unblock operations',
              new_pin: 'optional - replacement PIN in memory for change or unblock',
              new_puk: 'optional - replacement PUK in memory for change-puk',
              management_key: 'optional - raw binary management key supplied only in memory',
              new_management_key: 'optional - raw binary replacement management key',
              password: 'optional - in-memory PEM or PKCS12 import password',
              secret_provider: 'optional - callable receiving a missing secret field Symbol',
              secret_sink: 'optional - callable receiving field and newly generated unprotected management key',
              input: 'optional - binary input for a dash filename; no implicit terminal reads',
              use_protected_key: 'optional - literal true selects PIN-protected PIVMAN authentication',
              block_retries: 'optional - literal true explicitly authorizes PIN and PUK blocking before reset',
              public_key_source: 'optional - metadata, attestation or certificate; no error-triggered fallback',
              fips_restrictions: 'optional - Boolean for newer FIPS device capability restrictions',
              not_before: 'optional - Time for generated certificate start, default current UTC time',
              not_after: 'optional - Time for generated certificate expiry, default valid-days',
              certificate_serial: 'optional - positive integer certificate serial under 160 bits',
              extensions: 'optional - Array of OpenSSL X509 Extension objects',
              timeout: 'optional - finite positive APDU timeout seconds, default 30'
            )
            # Verify the supplied PIN exactly once without guessing credentials.
            #{self}.verify_pin(connection: 'required - APDU connection', pin: 'required - PIN in memory', confirm: 'required - literal true')
            # Mutually authenticate with the configured 3DES or AES management key.
            #{self}.authenticate(connection: 'required - APDU connection', management_key: 'required - raw binary secret', confirm: 'required - literal true')
            # Create a device-backed RSA, ECDSA or Ed25519 signature.
            #{self}.sign(
              connection: 'required - APDU connection', slot: 'required - PIV slot hex String or Integer',
              message: 'required - binary message String', algorithm: 'optional - algorithm name, otherwise slot metadata',
              hash_algorithm: 'optional - SHA1, SHA256, SHA384 or SHA512; default SHA256',
              padding: 'optional - pkcs1 or pss for RSA; default pkcs1',
              prehashed: 'optional - Boolean to use a digest instead of hashing the input',
              salt_length: 'optional - PSS salt length in bytes; default digest size',
              mgf1_hash: 'optional - PSS or OAEP MGF1 hash; default hash_algorithm',
              pin: 'optional - current PIN; the card enforces its policy if omitted', confirm: 'required - literal true'
            )
            # Decrypt a device-backed RSA ciphertext with native OpenSSL padding.
            #{self}.decrypt(
              connection: 'required - APDU connection', slot: 'required - PIV key slot',
              ciphertext: 'required - binary RSA ciphertext', padding: 'optional - oaep, pkcs1 or none; default oaep',
              label: 'optional - binary OAEP label', pin: 'optional - current PIN', confirm: 'required - literal true'
            )
            # Derive a device-backed ECDH or X25519 shared secret.
            #{self}.calculate_secret(
              connection: 'required - APDU connection', slot: 'required - PIV key slot',
              peer_public_key: 'required - PEM, DER or OpenSSL peer public key', pin: 'optional - current PIN', confirm: 'required - literal true'
            )
            # Verify an enrolled biometric and optionally request temporary PIN bytes.
            #{self}.verify_uv(connection: 'required - APDU connection', confirm: 'required - literal true', request_temporary_pin: 'optional - Boolean to request a session-local PIN')
            # Verify a card-issued temporary PIN during its session lifetime.
            #{self}.verify_temporary_pin(connection: 'required - APDU connection', confirm: 'required - literal true', temporary_pin: 'required - sixteen raw bytes in memory')
            # List the implemented PIV leaf catalog without device operations.
            #{self}.operations(prefix: 'optional - exact operation prefix filter')
            # Identify the module authors.
            #{self}.authors
          HELP
        end

        # Identify the module authors.
        # @return [String] authors
        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # A selected connection owns authentication state for its lifetime.
        class Session # rubocop:disable Metrics/ClassLength
          def initialize(opts)
            raise ArgumentError, 'PIV options must be a Hash' unless opts.is_a?(Hash)

            @opts = opts
            validate_options
            @connection = opts[:connection]
            @selected = false
          end

          def execute(args)
            raise ArgumentError, 'args must be an Array of Strings' unless args.is_a?(Array) && args.all?(String)

            return { application: :piv, operations: GRAMMAR.keys } if args.empty? || %w[access keys certificates objects].include?(args.join(' ')) || args == ['--help']

            operation = GRAMMAR.keys.sort_by(&:length).reverse.find { |name| args.first(name.split.length) == name.split }
            raise ArgumentError, 'Unknown PIV operation' unless operation

            count, flags, values = GRAMMAR.fetch(operation)
            parsed = Protocol.parse_args(args: args.drop(operation.split.length), flags: flags.map { |flag| "--#{flag}" }, values: values.map { |value| "--#{value}" })
            positions = parsed.fetch(:positionals)
            raise ArgumentError, 'Incorrect number of PIV arguments' unless count.is_a?(Range) ? count.cover?(positions.length) : positions.length == count

            @opts = @opts.merge(parsed.fetch(:options))
            validate_options
            output_index = { 'keys generate' => 1, 'keys export' => 1, 'keys attest' => 1, 'objects export' => 1,
                             'certificates export' => 1, 'certificates request' => 2 }[operation]
            if output_index && positions[output_index] != '-'
              confirm!
              path = positions.fetch(output_index)
              raise Errno::EEXIST, 'PIV output already exists' if File.exist?(path) || File.symlink?(path)
              raise Errno::ENOENT, 'PIV output parent does not exist' unless File.directory?(File.dirname(path))
            end
            case operation
            when 'info' then info
            when 'reset' then reset
            when 'access change-pin' then change_reference(0x24, 0x80, :pin, :new_pin)
            when 'access change-puk' then change_reference(0x24, 0x81, :puk, :new_puk)
            when 'access unblock-pin' then change_reference(0x2c, 0x80, :puk, :new_pin)
            when 'access set-retries' then set_retries(*positions)
            when 'access change-management-key' then change_management_key
            when 'objects import' then import_object(*positions)
            when 'objects export'
              id = parse_object_id(positions[0])
              verify_pin if @opts[:pin]
              output(read_object(id), positions[1])
            when 'objects generate' then generate_object(positions[0])
            when 'keys generate' then output(encode(generate_key(positions[0])), positions[1])
            when 'keys import' then import_key(positions[0], input(positions[1]))
            when 'keys info' then metadata(slot(positions[0]))
            when 'keys export' then output(encode(export_key(positions[0])), positions[1])
            when 'keys attest' then output(encode(attest(positions[0])), positions[1])
            when 'keys move' then move_key(*positions)
            when 'keys delete' then move_key(positions[0], nil)
            when 'certificates import' then import_certificate(positions[0], input(positions[1]))
            when 'certificates export' then output(encode(read_certificate(positions[0])), positions[1])
            when 'certificates generate' then generate_certificate(positions[0], positions[1] ? input(positions[1]) : nil)
            when 'certificates request' then output(encode(certificate_request(positions[0], input(positions[1]))), positions[2])
            when 'certificates delete' then delete_certificate(positions[0])
            else raise ArgumentError, 'Unknown PIV operation'
            end
          end

          def verify_pin(pin = nil)
            confirm!
            reference_apdu(0x20, p2: 0x80, data: pin_bytes(pin || secret(:pin)))
            :verified
          end

          def verify_uv(request_pin: false)
            raise ArgumentError, 'request_temporary_pin must be a Boolean' unless [true, false, nil].include?(request_pin)

            confirm!
            biometric_support
            response = reference_apdu(0x20, p2: 0x96, data: tlv(request_pin ? 2 : 3))
            raise ResponseError, 'Invalid temporary PIN length' if request_pin && response.bytesize != 16

            request_pin ? response : :verified
          end

          def verify_temporary_pin(value)
            confirm!
            value ||= secret(:temporary_pin)
            raise ArgumentError, 'temporary_pin must contain exactly 16 bytes' unless value.is_a?(String) && value.bytesize == 16

            biometric_support
            reference_apdu(0x20, p2: 0x96, data: tlv(1, value))
            :verified
          end

          def authenticate(key = nil)
            confirm!
            key ||= secret(:management_key)
            algorithm = management_algorithm
            id, size, cipher_name = MANAGEMENT.fetch(algorithm)
            require_version([5, 4, 0]) unless id == 3
            raise ArgumentError, 'Invalid management key length' unless key.is_a?(String) && key.bytesize == size

            witness = unpack(0x80, unpack(0x7c, apdu(0x87, p1: id, p2: 0x9b, data: tlv(0x7c, tlv(0x80)))))
            challenge_size = id == 3 ? 8 : 16
            raise ResponseError, 'Malformed management authentication witness' unless witness.bytesize == challenge_size

            cipher = OpenSSL::Cipher.new(cipher_name)
            cipher.decrypt
            cipher.padding = 0
            cipher.key = key
            plain = cipher.update(witness) + cipher.final
            challenge = SecureRandom.random_bytes(challenge_size)
            response = unpack(0x82, unpack(0x7c, apdu(0x87, p1: id, p2: 0x9b, data: tlv(0x7c, tlv(0x80, plain) + tlv(0x81, challenge)))))
            cipher.encrypt
            cipher.padding = 0
            cipher.key = key
            expected = cipher.update(challenge) + cipher.final
            raise ResponseError, 'Management authentication response does not verify' unless response.bytesize == expected.bytesize && OpenSSL.fixed_length_secure_compare(response, expected)

            :authenticated
          end

          def change_reference(ins, reference, current_name, new_name)
            confirm!
            current_value = secret(current_name)
            replacement_value = secret(new_name)
            current = pin_bytes(current_value)
            replacement = pin_bytes(replacement_value)
            data = pivman if current_name == :pin
            reference_apdu(ins, p2: reference, data: current + replacement)
            if data&.key?(0x82)
              old_key = OpenSSL::PKCS5.pbkdf2_hmac(current_value, data.fetch(0x82), 10_000, 24, 'SHA1')
              authenticate(old_key)
              verify_pin(replacement_value)
              salt = SecureRandom.random_bytes(16)
              new_key = OpenSSL::PKCS5.pbkdf2_hmac(replacement_value, salt, 10_000, 24, 'SHA1')
              set_management_key('TDES', new_key)
              authenticate(new_key)
              data[0x82] = salt
              write_object(0x5fff00, container(0x80, data))
            end
            { status: :changed, reference: reference }
          end

          def set_retries(pin_retries, puk_retries)
            pin_count = integer(pin_retries, 1..255)
            puk_count = integer(puk_retries, 0..255)
            confirm!
            pin = secret(:pin)
            pin_bytes(pin)
            if version_at_least?([5, 3, 0])
              begin
                metadata(0x96)
                raise UnsupportedError, 'PIN/PUK retries cannot be changed on biometric PIV'
              rescue Error => e
                raise unless [0x6a88, 0x6d00].include?(status_word(e))
              end
              raise UnsupportedError, 'FIPS retry limits must be set before changing PIN/PUK' if @opts[:fips_restrictions] && !(metadata(0x80).fetch(:default) && metadata(0x81).fetch(:default))
            end
            data = pivman
            admin_authenticate
            verify_pin(pin)
            apdu(0xfa, p1: pin_count, p2: puk_count)
            raise ResponseError, 'PIN/PUK retry-limit readback mismatch' if version_at_least?([5, 3, 0]) && !(metadata(0x80).fetch(:total_attempts) == pin_count && metadata(0x81).fetch(:total_attempts) == puk_count)

            if data.fetch(0x81, "\x00".b).getbyte(0).anybits?(1)
              data[0x81] = [data.fetch(0x81).getbyte(0) & ~1].pack('C')
              write_object(0x5fff00, container(0x80, data))
            end
            { status: :changed, pin_retries: pin_count, puk_retries: puk_count, references_reset: true }
          end

          def import_object(identifier, source)
            id = parse_object_id(identifier)
            bytes = input(source)
            confirm!
            if id == 0x5fc109
              data = pivman
              raise ArgumentError, 'Cannot overwrite protected management-key object' if data.key?(0x82) || data.fetch(0x81, "\x00".b).getbyte(0).anybits?(2)
            end
            admin_authenticate
            write_object(id, bytes)
          end

          def generate_object(identifier)
            id = parse_object_id(identifier)
            raise ArgumentError, 'Only CHUID and CCC can be generated' unless [0x5fc102, 0x5fc107].include?(id)

            confirm!
            data = id == 0x5fc102 ? chuid : ccc
            admin_authenticate
            write_object(id, data)
          end

          def read_object(identifier)
            id = parse_object_id(identifier)
            unpack(id == 0x7e ? 0x7e : 0x53, apdu(0xcb, p1: 0x3f, p2: 0xff, data: tlv(0x5c, number_bytes(id))))
          end

          def write_object(identifier, bytes)
            confirm!
            id = parse_object_id(identifier)
            raise ArgumentError, 'Object data must be a String' unless bytes.is_a?(String)

            apdu(0xdb, p1: 0x3f, p2: 0xff, data: tlv(0x5c, number_bytes(id)) + tlv(0x53, bytes))
            observed = optional_object(id)
            raise ResponseError, 'PIV object write readback mismatch; do not retry automatically' unless observed == bytes || (bytes.empty? && observed.nil?)

            { status: :written, object_id: id, bytes: bytes.bytesize }
          end

          def change_management_key
            confirm!
            name = @opts[:algorithm] ? enum_name(@opts[:algorithm], MANAGEMENT) : management_algorithm
            id, size = MANAGEMENT.fetch(name)
            require_version([5, 4, 0]) unless id == 3
            require_version([4, 0, 0]) if @opts[:touch]
            raise UnsupportedError, 'TDES management keys are not allowed by FIPS restrictions' if @opts[:fips_restrictions] && id == 3
            raise ArgumentError, 'generate conflicts with new_management_key' if @opts[:generate] && @opts[:new_management_key]

            generated = @opts[:generate] || (@opts[:protect] && !@opts[:new_management_key])
            raise ArgumentError, 'Generated unprotected management key requires secret_sink to retain it securely' if generated && !@opts[:protect] && !@opts[:secret_sink].respond_to?(:call)

            replacement = generated ? SecureRandom.random_bytes(size) : secret(:new_management_key)
            raise ArgumentError, 'Invalid new management key length' unless replacement.bytesize == size

            data = pivman
            stored = data.fetch(0x81, "\x00".b).getbyte(0).anybits?(2)
            pin = secret(:pin) if @opts[:protect] || stored
            pin_bytes(pin) if pin
            admin_authenticate
            verify_pin(pin) if pin
            protected_fields = protected_pivman if @opts[:protect] || stored
            @opts[:secret_sink].call(:new_management_key, replacement.dup) if generated && !@opts[:protect]
            set_management_key(name, replacement, touch: @opts[:touch] == true)
            authenticate(replacement)
            verify_pin(pin) if pin
            data.delete(0x82)
            flags = data.fetch(0x81, "\x00".b).getbyte(0)
            flags = @opts[:protect] ? flags | 2 : flags & ~2
            data[0x81] = [flags].pack('C')
            if protected_fields
              @opts[:protect] ? protected_fields[0x89] = replacement : protected_fields.delete(0x89)
              write_object(0x5fc109, container(0x88, protected_fields))
            end
            write_object(0x5fff00, container(0x80, data))
            { status: :changed, algorithm: name, protected: @opts[:protect] == true }
          end

          def sign(identifier, message, algorithm: nil)
            selected = slot(identifier)
            raise ArgumentError, 'message must be a String' unless message.is_a?(String)

            confirm!
            algorithm ||= @opts[:algorithm] || metadata(selected).fetch(:algorithm)
            algorithm = enum_name(algorithm, ALGORITHMS)
            raise ArgumentError, 'X25519 is a key-agreement algorithm, not a signature algorithm' if algorithm == 'X25519'

            policies(algorithm, generate: false)
            padded = signature_input(algorithm, message.b)
            crypto_pin
            private_operation(selected, algorithm, padded)
          end

          def decrypt(identifier, ciphertext)
            selected = slot(identifier)
            raise ArgumentError, 'ciphertext must be a String' unless ciphertext.is_a?(String)

            algorithm = "RSA#{ciphertext.bytesize * 8}"
            raise ArgumentError, 'Invalid RSA ciphertext size' unless ALGORITHMS.key?(algorithm)

            padding = @opts.fetch(:padding, :oaep).to_sym
            raise ArgumentError, 'RSA decryption padding must be oaep, pkcs1 or none' unless %i[oaep pkcs1 none].include?(padding)

            digest = digest_name
            confirm!
            policies(algorithm, generate: false)
            crypto_pin
            padded = private_operation(selected, algorithm, ciphertext.b)
            raise ResponseError, 'Invalid RSA result size' unless padded.bytesize == ciphertext.bytesize
            return padded if padding == :none

            # The host only handles padding: an unrelated ephemeral key sends the
            # raw device result through OpenSSL's hardened padding implementation.
            dummy = OpenSSL::PKey::RSA.generate(ciphertext.bytesize * 8)
            wrapped = dummy.encrypt(padded, 'rsa_padding_mode' => 'none')
            options = { 'rsa_padding_mode' => padding == :oaep ? 'oaep' : 'pkcs1' }
            options['rsa_pkcs1_implicit_rejection'] = '0' if padding == :pkcs1 && OpenSSL::OPENSSL_VERSION_NUMBER >= 0x30200000
            if padding == :oaep
              options['rsa_oaep_md'] = digest
              options['rsa_mgf1_md'] = @opts.fetch(:mgf1_hash, digest)
              options['rsa_oaep_label'] = @opts[:label].b.unpack1('H*') if @opts[:label]
            end
            message = dummy.decrypt(wrapped, options)
            # OpenSSL 3 may return random bytes instead of raising when PKCS1
            # padding is invalid. Never treat that as plaintext.
            if padding == :pkcs1
              verified = pkcs1_unpad(padded)
              raise ResponseError, 'RSA decryption failed' unless verified == message
            end
            message
          rescue OpenSSL::OpenSSLError
            raise ResponseError, 'RSA decryption failed', cause: nil
          end

          def pkcs1_unpad(padded)
            bytes = padded.b.bytes
            tail = bytes[2..] || []
            found = tail.index(0)
            separator = found.nil? ? nil : found + 2
            raise ResponseError, 'RSA decryption failed' unless bytes[0].zero? && bytes[1] == 2 && separator && separator >= 10

            padded.b.byteslice(separator + 1, padded.bytesize - separator - 1)
          end

          def calculate_secret(identifier, peer)
            selected = slot(identifier)
            public_part = parse_key(peer)
            algorithm = key_algorithm(public_part)
            raise ArgumentError, 'Key agreement requires P-256, P-384 or X25519' unless %w[ECCP256 ECCP384 X25519].include?(algorithm)

            confirm!
            policies(algorithm, generate: false)
            bytes = algorithm == 'X25519' ? public_part.raw_public_key : public_part.public_key.to_octet_string(:uncompressed)
            crypto_pin
            result = private_operation(selected, algorithm, bytes, exponentiation: true)
            raise ResponseError, 'Invalid key agreement result' unless result.bytesize == ALGORITHMS.fetch(algorithm)[1] && result.bytes.any?(&:positive?)

            result
          end

          def generate_key(identifier)
            selected = slot(identifier)
            algorithm = enum_name(@opts.fetch(:algorithm, 'RSA2048'), ALGORITHMS)
            policy = policies(algorithm, generate: true)
            confirm!
            admin_authenticate
            response = apdu(0x47, p2: selected, data: tlv(0xac, tlv(0x80, [ALGORITHMS.fetch(algorithm)[0]].pack('C')) + policy))
            public_key(algorithm, unpack(0x7f49, response))
          end

          def import_key(identifier, bytes)
            selected = slot(identifier)
            confirm!
            key = parse_key(bytes, private_key: true)
            algorithm = key_algorithm(key)
            policy = policies(algorithm, generate: false)
            id, length = ALGORITHMS.fetch(algorithm)
            data = if key.is_a?(OpenSSL::PKey::RSA)
                     raise ArgumentError, 'RSA public exponent must be 65537' unless key.e.to_i == 65_537

                     [key.p, key.q, key.dmp1, key.dmq1, key.iqmp].each_with_index.map { |value, index| tlv(index + 1, number_bytes(value.to_i, length / 2)) }.join.b
                   elsif key.is_a?(OpenSSL::PKey::EC)
                     tlv(6, number_bytes(key.private_key.to_i, length))
                   else
                     tlv(algorithm == 'ED25519' ? 7 : 8, key.raw_private_key)
                   end
            admin_authenticate
            apdu(0xfe, p1: id, p2: selected, data: data + policy)
            if version_at_least?([5, 3, 0])
              observed = metadata(selected).fetch(:public_key)
              raise ResponseError, 'Imported public key readback mismatch' unless observed.public_to_der == key.public_to_der
            end
            { status: :imported, slot: selected, algorithm: algorithm }
          end

          def export_key(identifier)
            selected = slot(identifier)
            source = @opts.fetch(:public_key_source, :metadata).to_sym
            key = case source
                  when :metadata then metadata(selected).fetch(:public_key)
                  when :attestation then attest(selected).public_key
                  when :certificate then read_certificate(selected).public_key
                  else raise ArgumentError, 'public_key_source must be metadata, attestation or certificate; private keys cannot be exported'
                  end
            verify_key(selected, key) if @opts[:verify]
            key
          end

          def attest(identifier)
            selected = slot(identifier)
            require_version([4, 3, 0])
            OpenSSL::X509::Certificate.new(apdu(0xf9, p1: selected))
          rescue OpenSSL::X509::CertificateError
            raise ResponseError, 'Malformed PIV attestation certificate', cause: nil
          end

          def move_key(source, destination)
            from = slot(source)
            to = destination.nil? ? 0xff : slot(destination)
            raise ArgumentError, 'Source and destination slots must differ' if from == to

            confirm!
            require_version([5, 7, 0])
            original = metadata(from).fetch(:public_key)
            admin_authenticate
            apdu(0xf6, p1: to, p2: from)
            begin
              metadata(from)
              raise ResponseError, 'PIV source key still present after move/delete'
            rescue Error => e
              raise unless status_word(e) == 0x6a88
            end
            raise ResponseError, 'PIV moved key readback mismatch' if destination && metadata(to).fetch(:public_key).public_to_der != original.public_to_der

            { status: destination ? :moved : :deleted, source: from, destination: destination ? to : nil }
          end

          def reset
            confirm!
            begin
              bio = metadata(0x96)
              raise UnsupportedError, 'Cannot reset PIV with enrolled biometrics; a full-device reset is required' if bio[:configured]
            rescue UnsupportedError
              raise if bio
            rescue Error => e
              raise unless [0x6a88, 0x6d00].include?(status_word(e))
            end
            if @opts[:block_retries] == true
              block_reference(0x20, "\xff".b * 8)
              block_reference(0x2c, "\xff".b * 16)
            end
            apdu(0xfb)
            @management_algorithm = nil
            raise ResponseError, 'PIV reset metadata is not default' if version_at_least?([5, 3, 0]) && !(metadata(0x80).fetch(:default) && metadata(0x9b).fetch(:default))

            { status: :reset, blocked_retries_authorized: @opts[:block_retries] == true }
          end

          def info
            result = { version: version, slots: {} }
            result[:serial] = apdu(0xf8).unpack1('H*').to_i(16) if version_at_least?([5, 0, 3])
            if version_at_least?([5, 3, 0])
              result[:pin] = metadata(0x80)
              result[:management_key] = metadata(0x9b)
              begin
                result[:biometrics] = metadata(0x96)
              rescue Error => e
                raise unless [0x6a88, 0x6d00].include?(status_word(e))

                result[:puk] = metadata(0x81)
              end
            else
              begin
                reference_apdu(0x20, p2: 0x80)
                result[:pin] = { verified: true, attempts_remaining: nil }
              rescue PinError => e
                result[:pin] = { attempts_remaining: e.attempts_remaining }
              end
              result[:management_key] = { algorithm: 'TDES' }
            end
            data = pivman
            result[:management_key][:protected] = data.key?(0x82) || data.fetch(0x81, "\x00".b).getbyte(0).anybits?(2)
            result[:chuid] = optional_object(0x5fc102)
            result[:ccc] = optional_object(0x5fc107)
            SLOTS.values.reject { |selected| selected == 0xf9 }.each do |selected|
              entry = {}
              if version_at_least?([5, 3, 0])
                begin
                  entry[:key] = metadata(selected)
                rescue Error => e
                  raise unless status_word(e) == 0x6a88
                end
              end
              begin
                certificate = read_certificate(selected)
                entry[:certificate] = { subject: certificate.subject.to_s, issuer: certificate.issuer.to_s, serial: certificate.serial.to_i,
                                        not_before: certificate.not_before, not_after: certificate.not_after, sha256: OpenSSL::Digest.hexdigest('SHA256', certificate.to_der) }
              rescue Error => e
                raise unless status_word(e) == 0x6a82
              end
              result[:slots][format('%02x', selected)] = entry unless entry.empty?
            end
            result
          end

          def read_certificate(identifier)
            fields = Protocol.tlv_map(data: read_object(certificate_object(slot(identifier))))
            bytes = field(fields, 0x70)
            compression = fields.fetch(0x71, "\x00".b)
            raise ResponseError, 'Unsupported certificate compression' unless ["\x00".b, "\x01".b].include?(compression)

            bytes = decompress(bytes) if compression == "\x01".b
            OpenSSL::X509::Certificate.new(bytes)
          rescue OpenSSL::X509::CertificateError
            raise ResponseError, 'Malformed PIV certificate', cause: nil
          end

          def import_certificate(identifier, bytes)
            selected = slot(identifier)
            confirm!
            certificate = parse_certificate(bytes)
            admin_authenticate
            verify_key(selected, certificate.public_key) if @opts[:verify]
            store_certificate(selected, certificate)
          end

          def delete_certificate(identifier)
            selected = slot(identifier)
            confirm!
            admin_authenticate
            result = write_object(certificate_object(selected), ''.b)
            result[:chuid] = update_chuid unless @opts[:no_update_chuid] || @opts[:update_chuid] == false
            result
          end

          def generate_certificate(identifier, bytes)
            selected = slot(identifier)
            confirm!
            key = bytes ? parse_key(bytes) : export_key(selected)
            algorithm = key_algorithm(key)
            raise ArgumentError, 'X25519 cannot self-sign a certificate' if algorithm == 'X25519'

            subject = certificate_subject
            days = integer(@opts.fetch(:valid_days, 365), 1..36_500)
            not_before = @opts.fetch(:not_before, Time.now.utc)
            not_after = @opts.fetch(:not_after, not_before + (days * 86_400))
            raise ArgumentError, 'Invalid certificate validity times' unless not_before.is_a?(Time) && not_after.is_a?(Time) && not_after > not_before

            asn1 = OpenSSL::ASN1
            signature_algorithm = signature_identifier(algorithm)
            serial = @opts.fetch(:certificate_serial, SecureRandom.random_number((2**159) - 1) + 1)
            raise ArgumentError, 'Certificate serial must be a positive integer under 160 bits' unless serial.is_a?(Integer) && serial.positive? && serial.bit_length <= 159

            fields = [asn1::ASN1Data.new([asn1::Integer.new(2)], 0, :CONTEXT_SPECIFIC), asn1::Integer.new(serial), signature_algorithm,
                      asn1.decode(subject.to_der), asn1::Sequence.new([asn1_time(not_before), asn1_time(not_after)]),
                      asn1.decode(subject.to_der), asn1.decode(key.public_to_der)]
            extensions = @opts.fetch(:extensions, [])
            raise ArgumentError, 'extensions must be an Array of X509 extensions' unless extensions.is_a?(Array) && extensions.all?(OpenSSL::X509::Extension)

            fields << asn1::ASN1Data.new([asn1::Sequence.new(extensions.map { |ext| asn1.decode(ext.to_der) })], 3, :CONTEXT_SPECIFIC) unless extensions.empty?
            tbs = asn1::Sequence.new(fields)
            admin_authenticate
            signature = sign(selected, tbs.to_der, algorithm: algorithm)
            certificate = OpenSSL::X509::Certificate.new(asn1::Sequence.new([tbs, signature_algorithm, asn1::BitString.new(signature)]).to_der)
            raise ResponseError, 'Device-signed certificate does not verify against supplied public key' unless certificate.verify(key)

            store_certificate(selected, certificate).merge(certificate: encode(certificate))
          end

          def certificate_request(identifier, bytes)
            selected = slot(identifier)
            confirm!
            key = parse_key(bytes)
            algorithm = key_algorithm(key)
            raise ArgumentError, 'X25519 cannot sign a CSR' if algorithm == 'X25519'

            asn1 = OpenSSL::ASN1
            info = asn1::Sequence.new([asn1::Integer.new(0), asn1.decode(certificate_subject.to_der), asn1.decode(key.public_to_der), asn1::ASN1Data.new([], 0, :CONTEXT_SPECIFIC)])
            signature_algorithm = signature_identifier(algorithm)
            signature = sign(selected, info.to_der, algorithm: algorithm)
            csr = OpenSSL::X509::Request.new(asn1::Sequence.new([info, signature_algorithm, asn1::BitString.new(signature)]).to_der)
            raise ResponseError, 'Device-signed CSR does not verify against supplied public key' unless csr.verify(key)

            csr
          end

          def version
            @version ||= begin
              response = apdu(0xfd)
              raise ResponseError, 'Invalid PIV version response' unless response.bytesize == 3

              response.bytes
            end
          end

          def metadata(reference)
            require_version([5, 3, 0])
            fields = Protocol.tlv_map(data: apdu(0xf7, p2: reference))
            case reference
            when 0x80, 0x81
              attempts = field(fields, 6, 2).bytes
              { default: field(fields, 5, 1) != "\x00".b, total_attempts: attempts[0], attempts_remaining: attempts[1] }
            when 0x9b
              id = fields.fetch(1, "\x03".b).getbyte(0)
              name = MANAGEMENT.keys.find { |key| MANAGEMENT[key][0] == id }
              raise ResponseError, 'Unknown management algorithm' unless name

              { algorithm: name, default: field(fields, 5, 1) != "\x00".b, touch_policy: field(fields, 2, 2).getbyte(1) }
            when 0x96
              { configured: field(fields, 7, 1).getbyte(0) == 1, attempts_remaining: field(fields, 6, 1).getbyte(0), temporary_pin: fields.fetch(8, "\x00".b).getbyte(0) == 1 }
            else
              id = field(fields, 1, 1).getbyte(0)
              algorithm = ALGORITHMS.keys.find { |key| ALGORITHMS[key][0] == id }
              raise ResponseError, 'Unknown PIV key algorithm' unless algorithm

              policy = field(fields, 2, 2).bytes
              { algorithm: algorithm, pin_policy: PIN_POLICIES.key(policy[0]), touch_policy: TOUCH_POLICIES.key(policy[1]),
                generated: field(fields, 3, 1).getbyte(0) == 1, public_key: public_key(algorithm, field(fields, 4)) }
            end
          end

          private

          def biometric_support
            metadata(0x96)
          rescue Error => e
            raise UnsupportedError, 'Biometric verification is not supported by this PIV device', cause: nil if [0x6a88, 0x6d00].include?(status_word(e))

            raise
          end

          def validate_options
            flags = %i[protect generate touch use_protected_key verify compress update_chuid no_update_chuid block_retries prehashed fips_restrictions]
            flags.each do |flag|
              raise ArgumentError, "#{flag} must be a Boolean" if @opts.key?(flag) && ![true, false].include?(@opts[flag])
            end
            raise ArgumentError, 'Conflicting CHUID update options' if @opts[:update_chuid] && @opts[:no_update_chuid]
            raise ArgumentError, 'format must be PEM or DER' if @opts[:format] && !%w[PEM DER].include?(@opts[:format].to_s.upcase)
            raise ArgumentError, 'label must be binary String' if @opts[:label] && !@opts[:label].is_a?(String)
            raise ArgumentError, 'mgf1_hash must be SHA1, SHA256, SHA384 or SHA512' if @opts[:mgf1_hash] && !%w[SHA1 SHA256 SHA384 SHA512].include?(@opts[:mgf1_hash].to_s.upcase)

            digest_name if @opts[:hash_algorithm]
          end

          def block_reference(ins, data)
            # Only reachable with BOTH confirm:true and block_retries:true. Empty
            # padded references are deliberately invalid, never factory guesses.
            previous = 256
            256.times do
              reference_apdu(ins, p2: 0x80, data: data)
              raise ResponseError, 'Unexpected successful blocking attempt; reset stopped'
            rescue PinError => e
              return :blocked if e.attempts_remaining.zero?
              # Firmware caps SW retries at 15; allow that plateau only.
              raise ResponseError, 'PIN/PUK retry counter did not decrease; reset stopped' if e.attempts_remaining > previous || (e.attempts_remaining == previous && previous != 15)

              previous = e.attempts_remaining
            end
            raise ResponseError, 'PIV blocking limit exceeded; reset stopped'
          end

          def certificate_object(selected)
            return 0x5fc10d + selected - 0x82 if (0x82..0x95).cover?(selected)

            { 0x9a => 0x5fc105, 0x9c => 0x5fc10a, 0x9d => 0x5fc10b, 0x9e => 0x5fc101, 0xf9 => 0x5fff01 }.fetch(selected)
          end

          def store_certificate(selected, certificate)
            bytes = certificate.to_der
            if @opts[:compress]
              buffer = StringIO.new(''.b)
              gzip = Zlib::GzipWriter.new(buffer)
              gzip.write(bytes)
              gzip.close
              bytes = buffer.string
            end
            result = write_object(certificate_object(selected), tlv(0x70, bytes) + tlv(0x71, @opts[:compress] ? "\x01".b : "\x00".b) + tlv(0xfe))
            result[:chuid] = update_chuid unless @opts[:no_update_chuid] || @opts[:update_chuid] == false
            result
          end

          def update_chuid
            original = optional_object(0x5fc102)
            if original && !original.empty?
              begin
                fields = Protocol.tlv_map(data: original)
                return :preserved unless fields.key?(0x30) && fields.key?(0x35) && fields[0x34]&.bytesize == 16 && fields[0x3e] == ''.b

                fields[0x34] = [SecureRandom.uuid.delete('-')].pack('H*')
                replacement = fields.map { |tag, data| tlv(tag, data) }.join.b
              rescue ResponseError
                return :preserved
              end
            else
              replacement = chuid
            end
            write_object(0x5fc102, replacement)
            :updated
          end

          def decompress(bytes)
            limit = 65_536
            if bytes.start_with?("\x1f\x8b".b)
              reader = Zlib::GzipReader.new(StringIO.new(bytes))
              begin
                result = reader.read(limit + 1)
              ensure
                reader.close
              end
            elsif bytes.start_with?("\x01\x00".b) && bytes.bytesize >= 4
              expected = bytes.byteslice(2, 2).unpack1('v')
              inflater = Zlib::Inflate.new
              begin
                result = ''.b
                inflater.inflate(bytes.byteslice(4..)) do |chunk|
                  result << chunk
                  raise ResponseError, 'Decompressed certificate exceeds limit' if result.bytesize > limit
                end
                raise ResponseError, 'Compressed certificate length mismatch' unless result.bytesize == expected && inflater.finished?
              ensure
                inflater.close
              end
            else
              raise ResponseError, 'Unknown certificate compression format'
            end
            raise ResponseError, 'Decompressed certificate exceeds limit' if result.bytesize > limit

            result
          rescue Zlib::Error, EOFError
            raise ResponseError, 'Invalid compressed certificate', cause: nil
          end

          def parse_certificate(bytes)
            return bytes if bytes.is_a?(OpenSSL::X509::Certificate)

            blocks = bytes.scan(/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/m)
            certificates = if blocks.empty?
                             begin
                               [OpenSSL::X509::Certificate.new(bytes)]
                             rescue OpenSSL::X509::CertificateError
                               archive = OpenSSL::PKCS12.new(bytes, @opts[:password] || '')
                               [archive.certificate, *archive.ca_certs].compact
                             end
                           else
                             blocks.map { |block| OpenSSL::X509::Certificate.new(block) }
                           end
            leaves = certificates.reject { |candidate| certificates.any? { |other| other != candidate && other.issuer.to_der == candidate.subject.to_der } }
            raise ArgumentError, 'Certificate input must contain one unambiguous leaf' unless leaves.size == 1

            leaves.first
          rescue OpenSSL::OpenSSLError
            raise ArgumentError, 'Invalid certificate or PKCS12 password', cause: nil
          end

          def certificate_subject
            value = @opts[:subject]
            return value if value.is_a?(OpenSSL::X509::Name)
            raise ArgumentError, 'subject is required' unless value.is_a?(String) && !value.empty?

            value = "CN=#{value}" unless value.include?('=')
            OpenSSL::X509::Name.parse_rfc2253(value)
          rescue OpenSSL::X509::NameError
            raise ArgumentError, 'Invalid RFC4514 certificate subject', cause: nil
          end

          def signature_identifier(algorithm)
            raise ArgumentError, 'Certificates and CSRs use PKCS1 signature padding' if @opts[:padding] && @opts[:padding].to_sym != :pkcs1
            raise ArgumentError, 'Certificates and CSRs cannot sign prehashed inputs' if @opts[:prehashed]

            asn1 = OpenSSL::ASN1
            digest = digest_name
            oid = if algorithm == 'ED25519'
                    'ED25519'
                  elsif algorithm.start_with?('RSA')
                    "#{digest.downcase}WithRSAEncryption"
                  else
                    "ecdsa-with-#{digest}"
                  end
            values = [asn1::ObjectId.new(oid)]
            values << asn1::Null.new(nil) if algorithm.start_with?('RSA')
            asn1::Sequence.new(values)
          end

          def asn1_time(time)
            (1950..2049).cover?(time.year) ? OpenSSL::ASN1::UTCTime.new(time.utc) : OpenSSL::ASN1::GeneralizedTime.new(time.utc)
          end

          def crypto_pin
            verify_pin if @opts[:pin] || @opts[:secret_provider]
          end

          def private_operation(selected, algorithm, bytes, exponentiation: false)
            confirm!
            unpack(0x82, unpack(0x7c, apdu(0x87, p1: ALGORITHMS.fetch(algorithm)[0], p2: selected, data: tlv(0x7c, tlv(0x82) + tlv(exponentiation ? 0x85 : 0x81, bytes)))))
          end

          def digest_name
            name = @opts.fetch(:hash_algorithm, 'SHA256').to_s.upcase
            raise ArgumentError, 'hash_algorithm must be SHA1, SHA256, SHA384 or SHA512' unless %w[SHA1 SHA256 SHA384 SHA512].include?(name)

            name
          end

          def signature_input(algorithm, message)
            return message if algorithm == 'ED25519'

            digest = digest_name
            hashed = @opts[:prehashed] ? message : OpenSSL::Digest.digest(digest, message)
            raise ArgumentError, 'Prehashed message has the wrong digest size' unless hashed.bytesize == OpenSSL::Digest.new(digest).digest_length

            size = ALGORITHMS.fetch(algorithm)[1]
            return hashed.byteslice(0, size).rjust(size, "\x00".b) if algorithm.start_with?('ECC')

            padding = @opts.fetch(:padding, :pkcs1).to_sym
            return pss_encode(hashed, size, digest) if padding == :pss
            raise ArgumentError, 'RSA signature padding must be pkcs1 or pss' unless padding == :pkcs1

            asn1 = OpenSSL::ASN1
            info = asn1::Sequence.new([asn1::Sequence.new([asn1::ObjectId.new(digest), asn1::Null.new(nil)]), asn1::OctetString.new(hashed)]).to_der
            raise ArgumentError, 'Digest too large for RSA signature' if size < info.bytesize + 11

            "\x00\x01".b + ("\xff".b * (size - info.bytesize - 3)) + "\x00".b + info
          end

          def pss_encode(hashed, size, digest)
            salt_length = integer(@opts.fetch(:salt_length, hashed.bytesize), 0..(size - hashed.bytesize - 2))
            salt = SecureRandom.random_bytes(salt_length)
            h = OpenSSL::Digest.digest(digest, ("\x00".b * 8) + hashed + salt)
            data = ("\x00".b * (size - hashed.bytesize - salt_length - 2)) + "\x01".b + salt
            masked = xor_bytes(data, mgf1(h, data.bytesize, @opts.fetch(:mgf1_hash, digest)))
            masked.setbyte(0, masked.getbyte(0) & 0x7f)
            masked + h + "\xbc".b
          end

          def mgf1(seed, length, digest)
            output = ''.b
            counter = 0
            while output.bytesize < length
              output << OpenSSL::Digest.digest(digest, seed + [counter].pack('N'))
              counter += 1
            end
            output.byteslice(0, length)
          end

          def xor_bytes(left, right)
            left.bytes.zip(right.bytes).map { |a, b| a ^ b }.pack('C*')
          end

          def verify_key(selected, key)
            confirm!
            algorithm = key_algorithm(key)
            if algorithm == 'X25519'
              peer = OpenSSL::PKey.generate_key('X25519')
              shared = calculate_secret(selected, OpenSSL::PKey.read(peer.public_to_der))
              expected = peer.derive(key)
              valid = OpenSSL.fixed_length_secure_compare(shared, expected)
            else
              challenge = SecureRandom.random_bytes(32)
              signature = sign(selected, challenge, algorithm: algorithm)
              valid = key.verify(algorithm == 'ED25519' ? nil : digest_name, signature, challenge)
            end
            raise ResponseError, 'Public key does not match the device private key' unless valid

            :verified
          end

          def slot(value)
            return value if value.is_a?(Integer) && SLOTS.value?(value)

            name = value.to_s.upcase.tr('-', '_')
            return SLOTS.fetch(name) if SLOTS.key?(name)
            raise ArgumentError, 'Invalid PIV key slot' unless value.is_a?(String) && value.match?(/\A(?:0x)?[0-9a-fA-F]{2}\z/) && SLOTS.value?(value.to_i(16))

            value.to_i(16)
          end

          def policies(algorithm, generate:)
            pin = PIN_POLICIES.fetch(enum_name(@opts.fetch(:pin_policy, 'DEFAULT'), PIN_POLICIES))
            touch = TOUCH_POLICIES.fetch(enum_name(@opts.fetch(:touch_policy, 'DEFAULT'), TOUCH_POLICIES))
            require_version([4, 0, 0]) if algorithm == 'ECCP384' || pin.positive? || touch.positive?
            require_version([4, 3, 0]) if touch == 3
            require_version([5, 7, 0]) if %w[RSA3072 RSA4096 ED25519 X25519].include?(algorithm)
            raise UnsupportedError, 'RSA generation is disabled for ROCA-vulnerable firmware' if generate && algorithm.start_with?('RSA') && version_at_least?([4, 2, 0]) && !version_at_least?([4, 3, 5])

            raise UnsupportedError, 'Algorithm or PIN policy forbidden by FIPS restrictions' if (@opts[:fips_restrictions] || (version_at_least?([4, 4, 0]) && !version_at_least?([4, 5, 0]))) && (%w[RSA1024 X25519].include?(algorithm) || pin == 1)

            if pin >= 4
              begin
                metadata(0x96)
              rescue Error => e
                raise UnsupportedError, 'MATCH policies require biometric PIV firmware', cause: nil if [0x6a88, 0x6d00].include?(status_word(e))

                raise
              end
            end
            (pin.positive? ? tlv(0xaa, [pin].pack('C')) : ''.b) + (touch.positive? ? tlv(0xab, [touch].pack('C')) : ''.b)
          end

          def public_key(algorithm, encoded)
            fields = Protocol.tlv_map(data: encoded)
            asn1 = OpenSSL::ASN1
            if algorithm.start_with?('RSA')
              n = OpenSSL::BN.new(field(fields, 0x81), 2)
              e = OpenSSL::BN.new(field(fields, 0x82), 2)
              rsa = asn1::Sequence.new([asn1::Integer.new(n), asn1::Integer.new(e)]).to_der
              der = asn1::Sequence.new([asn1::Sequence.new([asn1::ObjectId.new('rsaEncryption'), asn1::Null.new(nil)]), asn1::BitString.new(rsa)]).to_der
            else
              point = field(fields, 0x86)
              oids = case algorithm
                     when 'ECCP256' then %w[id-ecPublicKey prime256v1]
                     when 'ECCP384' then %w[id-ecPublicKey secp384r1]
                     else [algorithm]
                     end
              der = asn1::Sequence.new([asn1::Sequence.new(oids.map { |oid| asn1::ObjectId.new(oid) }), asn1::BitString.new(point)]).to_der
            end
            key = OpenSSL::PKey.read(der)
            raise ResponseError, 'Public key algorithm mismatch' unless key_algorithm(key) == algorithm

            key
          rescue OpenSSL::PKey::PKeyError, OpenSSL::ASN1::ASN1Error
            raise ResponseError, 'Malformed PIV public key', cause: nil
          end

          def key_algorithm(key)
            name = if key.is_a?(OpenSSL::PKey::RSA)
                     "RSA#{key.n.num_bits}"
                   elsif key.is_a?(OpenSSL::PKey::EC)
                     { 'prime256v1' => 'ECCP256', 'secp384r1' => 'ECCP384' }.fetch(key.group.curve_name, '')
                   else
                     key.oid
                   end
            enum_name(name, ALGORITHMS)
          end

          def parse_key(bytes, private_key: false)
            return bytes if bytes.is_a?(OpenSSL::PKey::PKey) && !private_key

            password = @opts[:password]
            password ||= secret(:password) if bytes.is_a?(String) && bytes.include?('ENCRYPTED') && @opts[:secret_provider]
            key = if bytes.is_a?(OpenSSL::PKey::PKey)
                    bytes
                  else
                    begin
                      OpenSSL::PKey.read(bytes, password || '')
                    rescue OpenSSL::PKey::PKeyError
                      raise unless private_key

                      OpenSSL::PKCS12.new(bytes, password || '').key || (raise ArgumentError, 'PKCS12 contains no private key')
                    end
                  end
            key.private_to_der if private_key
            key_algorithm(key)
            key
          rescue OpenSSL::OpenSSLError
            raise ArgumentError, 'Invalid key data or key password; private import requires a private key', cause: nil
          end

          def encode(value)
            encoding = @opts.fetch(:format, 'PEM').to_s.upcase
            raise ArgumentError, 'format must be PEM or DER' unless %w[PEM DER].include?(encoding)

            if value.is_a?(OpenSSL::PKey::PKey)
              encoding == 'PEM' ? value.public_to_pem : value.public_to_der
            else
              encoding == 'PEM' ? value.to_pem : value.to_der
            end
          end

          def input(path)
            data = path == '-' ? @opts[:input] : File.binread(path)
            raise ArgumentError, 'Binary input is required in opts[:input] for -' unless data.is_a?(String)

            data.b
          end

          def output(bytes, path)
            return bytes if path.nil? || path == '-'

            confirm!
            # Never clobber a caller's existing file on an uncertain operation.
            File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
              file.binmode
              file.write(bytes)
              file.flush
              file.fsync
            end
            raise IOError, 'PIV export readback mismatch' unless File.binread(path) == bytes

            bytes
          end

          def enum_name(value, table)
            name = value.to_s.upcase.tr('-', '_')
            raise ArgumentError, 'Invalid PIV algorithm or policy' unless table.key?(name)

            name
          end

          def parse_object_id(value)
            return value if value.is_a?(Integer) && (1..0xffffff).cover?(value)

            name = value.to_s.upcase.tr('-', '_')
            return OBJECTS.fetch(name) if OBJECTS.key?(name)
            raise ArgumentError, 'Invalid PIV object identifier' unless value.is_a?(String) && value.match?(/\A(?:0x)?[0-9a-fA-F]{1,6}\z/)

            number = value.to_i(16)
            raise ArgumentError, 'Invalid PIV object identifier' if number.zero?

            number
          end

          def number_bytes(number, length = nil)
            bytes = [number.to_s(16).rjust(2, '0').then { |hex| hex.length.odd? ? "0#{hex}" : hex }].pack('H*')
            length ? bytes.rjust(length, "\x00".b) : bytes
          end

          def optional_object(id)
            read_object(id)
          rescue Error => e
            raise unless status_word(e) == 0x6a82

            nil
          end

          def pivman
            bytes = optional_object(0x5fff00)
            bytes.nil? || bytes.empty? ? {} : Protocol.tlv_map(data: unpack(0x80, bytes))
          end

          def protected_pivman
            bytes = optional_object(0x5fc109)
            bytes.nil? || bytes.empty? ? {} : Protocol.tlv_map(data: unpack(0x88, bytes))
          end

          def container(tag, fields)
            tlv(tag, fields.map { |key, value| tlv(key, value) }.join.b)
          end

          def admin_authenticate
            return authenticate unless @opts[:use_protected_key] == true

            confirm!
            pin = secret(:pin)
            pin_bytes(pin)
            data = pivman
            verify_pin(pin)
            key = if data.key?(0x82)
                    OpenSSL::PKCS5.pbkdf2_hmac(pin, data.fetch(0x82), 10_000, 24, 'SHA1')
                  elsif data.fetch(0x81, "\x00".b).getbyte(0).anybits?(2)
                    protected_pivman.fetch(0x89) { raise ResponseError, 'Protected management key is absent' }
                  else
                    raise ArgumentError, 'No protected management key is configured'
                  end
            authenticate(key)
          end

          def set_management_key(name, key, touch: false)
            apdu(0xff, p1: 0xff, p2: touch ? 0xfe : 0xff, data: [MANAGEMENT.fetch(name)[0]].pack('C') + tlv(0x9b, key))
            @management_algorithm = name
          end

          def chuid
            # Non-federal issuer FASC-N from the SP 800-73 CHUID layout.
            digits = %w[9999 9999 999999 0 1 0000000000 3 0000 1]
            pieces = digits.map do |value|
              value.chars.map do |char|
                bits = char.to_i.to_s(2).rjust(4, '0').reverse
                bits + ((bits.count('1') + 1) % 2).to_s
              end.join
            end
            bits = "11010#{pieces.first(5).join('10110')}10110#{pieces.drop(5).join}11111"
            lrc = bits.scan(/.{5}/).map { |part| part.to_i(2) }.reduce(0, :^)
            fascn = [bits + lrc.to_s(2).rjust(5, '0')].pack('B*')
            guid = [SecureRandom.uuid.delete('-')].pack('H*')
            tlv(0x30, fascn) + tlv(0x34, guid) + tlv(0x35, '20300101') + tlv(0x3e) + tlv(0xfe)
          end

          def ccc
            tlv(0xf0, ['a000000116ff02'].pack('H*') + SecureRandom.random_bytes(14)) + tlv(0xf1, "\x21".b) + tlv(0xf2, "\x21".b) + tlv(0xf3) + tlv(0xf4, "\x00".b) + tlv(0xf5, "\x10".b) + [0xf6, 0xf7, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe].map { |tag| tlv(tag) }.join.b
          end

          def field(fields, tag, size = nil)
            value = fields[tag]
            raise ResponseError, 'Missing or malformed PIV response field' unless value.is_a?(String) && (size.nil? || value.bytesize == size)

            value
          end

          def pin_bytes(value)
            raise ArgumentError, 'PIN/PUK must contain 6 to 8 bytes' unless value.is_a?(String) && (6..8).cover?(value.bytesize)

            value.b.ljust(8, "\xff".b)
          end

          def integer(value, range)
            raise ArgumentError, 'Invalid integer argument' unless value.is_a?(Integer) || (value.is_a?(String) && value.match?(/\A[0-9]+\z/))

            number = value.to_i
            raise ArgumentError, 'Integer argument out of range' unless range.cover?(number)

            number
          end

          def management_algorithm
            @management_algorithm ||= version_at_least?([5, 3, 0]) ? metadata(0x9b).fetch(:algorithm) : 'TDES'
          end

          def version_at_least?(minimum)
            Protocol.version_at_least?(version: version, minimum: minimum)
          end

          def require_version(minimum)
            raise UnsupportedError, "PIV operation requires firmware #{minimum.join('.')} or later" unless version_at_least?(minimum)
          end

          def tlv(tag, value = ''.b)
            Protocol.tlv(tag: tag, value: value)
          end

          def unpack(tag, value)
            fields = Protocol.untlv(data: value)
            raise ResponseError, 'Malformed PIV response container' unless fields.length == 1 && fields.first[:tag] == tag

            fields.first.fetch(:value)
          end

          def status_word(error)
            return error.status if error.respond_to?(:status)
            return error.sw if error.respond_to?(:sw)
            return error.status_word if error.respond_to?(:status_word)

            nil
          end

          def reference_apdu(ins, **)
            apdu(ins, **)
          rescue Error => e
            sw = status_word(e)
            retries = if sw == 0x6983
                        0
                      elsif sw && sw & 0xfff0 == 0x63c0
                        sw & 15
                      elsif sw && sw & 0xff00 == 0x6300
                        sw & 255
                      end
            raise PinError.new(retries), cause: nil unless retries.nil?

            raise
          end

          def confirm!
            Protocol.require_confirm(@opts)
          end

          def secret(name)
            Protocol.secret(value: @opts[name], secret_provider: @opts[:secret_provider], name: name)
          end

          def apdu(ins, p1: 0, p2: 0, data: ''.b) # rubocop:disable Naming/MethodParameterName
            unless @selected
              Protocol.select(connection: @connection, aid: AID, timeout: @opts.fetch(:timeout, 30))
              @selected = true
            end
            Protocol.apdu(connection: @connection, ins: ins, p1: p1, p2: p2, data: data, timeout: @opts.fetch(:timeout, 30))
          end
        end
      end
    end
  end
end
