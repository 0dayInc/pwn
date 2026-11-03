# frozen_string_literal: true

require 'openssl'
require 'securerandom'
require 'pwn/plugins/yubikey'

module PWN
  module Plugins
    module YubiKey
      # Native CTAP/U2F application logic. Transport owns CTAPHID framing.
      # References: FIDO CTAP 2.1 PS (2021-06-15), U2F raw message formats 1.2,
      # RFC 8949; cross-checked against python-fido2 and YubiKey Manager 5.9.1.
      # No client/origin policy is fabricated: callers supply RP and client hashes.
      module FIDO
        class UnsupportedError < Error; end
        class Cancelled < Error; end

        # Status-only exception: never include packet bodies or PIN values.
        class CTAPError < CommandError
          attr_reader :code

          NAMES = { 0x01 => 'INVALID_COMMAND', 0x02 => 'INVALID_PARAMETER', 0x03 => 'INVALID_LENGTH', 0x05 => 'TIMEOUT', 0x11 => 'CBOR_UNEXPECTED_TYPE', 0x12 => 'INVALID_CBOR', 0x14 => 'MISSING_PARAMETER', 0x19 => 'CREDENTIAL_EXCLUDED', 0x27 => 'OPERATION_DENIED', 0x28 => 'KEY_STORE_FULL', 0x2b => 'UNSUPPORTED_OPTION', 0x2c => 'INVALID_OPTION', 0x2d => 'KEEPALIVE_CANCEL', 0x2e => 'NO_CREDENTIALS', 0x2f => 'USER_ACTION_TIMEOUT', 0x30 => 'NOT_ALLOWED', 0x31 => 'PIN_INVALID', 0x32 => 'PIN_BLOCKED', 0x33 => 'PIN_AUTH_INVALID', 0x34 => 'PIN_AUTH_BLOCKED', 0x35 => 'PIN_NOT_SET', 0x36 => 'PUAT_REQUIRED', 0x37 => 'PIN_POLICY_VIOLATION', 0x38 => 'PIN_TOKEN_EXPIRED', 0x3b => 'UP_REQUIRED', 0x3c => 'UV_BLOCKED', 0x3f => 'UV_INVALID', 0x40 => 'UNAUTHORIZED_PERMISSION' }.freeze

          def initialize(code)
            @code = code
            super(format('CTAP error 0x%<code>02x (%<name>s); operation was not retried', code: code, name: NAMES.fetch(code, 'UNKNOWN')))
          end
        end

        # U2F/PCSC error retaining the numeric status word only.
        class APDUError < CommandError
          attr_reader :code

          def initialize(code)
            @code = code
            super(format('FIDO APDU status 0x%04x; operation was not retried', code))
          end
        end

        # Enrollment is durable before naming. Expose recovery identity, not a retry.
        class EnrollmentError < Error
          attr_reader :template_id

          def initialize(template_id)
            @template_id = template_id
            super('Fingerprint enrolled, but naming failed; use template_id to rename; enrollment was not repeated or deleted')
          end
        end

        COMMANDS = {
          'info' => [:info, [], [], []],
          'reset' => [:reset, [], %w[force], []],
          'access change-pin' => [:change_pin, [], %w[u2f], []],
          'access verify-pin' => [:verify_pin, [], [], []],
          'access force-change' => [:force_change, [], [], []],
          'access set-min-length' => [:set_min_length, [:min_length], [], %w[rp-id]],
          'credentials list' => [:list_credentials, [], %w[csv], []],
          'credentials delete' => [:delete_credential, [:credential_id_hex], %w[force], []],
          'fingerprints list' => [:list_fingerprints, [], [], []],
          'fingerprints add' => [:add_fingerprint, [:name], [], []],
          'fingerprints rename' => [:rename_fingerprint, %i[template_id_hex name], [], []],
          'fingerprints delete' => [:delete_fingerprint, [:template_id_hex], %w[force], []],
          'config toggle-always-uv' => [:toggle_always_uv, [], [], []],
          'config enable-ep-attestation' => [:enable_enterprise_attestation, [], [], []]
        }.freeze
        GROUPS = ['', 'access', 'credentials', 'fingerprints', 'config'].freeze

        public_class_method def self.operations
          COMMANDS.keys
        end

        public_class_method def self.execute(opts = {})
          args = opts.key?(:args) ? opts[:args] : []
          raise ArgumentError, 'FIDO args must be an Array of nonsecret Strings' unless args.is_a?(Array) && args.size <= 256 && args.all? { |arg| arg.is_a?(String) && arg.bytesize <= 4096 }

          path = args.join(' ')
          return { group: path, operations: operations.select { |entry| path.empty? || entry.start_with?("#{path} ") } } if GROUPS.include?(path)

          path = COMMANDS.keys.sort_by { |entry| -entry.length }.find { |entry| args.first(entry.split.size) == entry.split }
          raise ArgumentError, 'Unknown FIDO operation' unless path

          method, positional_names, flags, values = COMMANDS.fetch(path)
          parsed = {}
          positional = []
          rest = args.drop(path.split.size)
          until rest.empty?
            arg = rest.shift
            if arg == '--'
              positional.concat(rest)
              break
            elsif arg.start_with?('--')
              name = arg.delete_prefix('--')
              if flags.include?(name)
                parsed[name.tr('-', '_').to_sym] = true
              elsif values.include?(name)
                value = rest.shift
                raise ArgumentError, 'Missing FIDO option value' unless value && !value.start_with?('--')

                (parsed[:rp_ids] ||= []) << value
              else
                raise ArgumentError, 'Unknown FIDO option; secrets belong in memory options, not args'
              end
            else
              positional << arg
            end
          end
          optional_name = method == :add_fingerprint && positional.empty?
          raise ArgumentError, 'Incorrect FIDO positional argument count' unless positional.size == positional_names.size || optional_name

          positional_names.zip(positional).each { |key, value| parsed[key] = value if value }
          perform(opts.merge(parsed).merge(operation: method))
        end

        public_class_method def self.perform(opts = {})
          operation = opts[:operation]
          allowed = COMMANDS.values.map(&:first) + %i[pin_retries update_credential bio_sensor_info cancel_enrollment make_credential get_assertion u2f_register u2f_authenticate]
          raise ArgumentError, 'Unknown native FIDO operation' unless allowed.include?(operation)

          session = Session.new(opts)
          session.run(operation)
        ensure
          session&.forget
        end

        public_class_method def self.make_credential(opts = {})
          perform(opts.merge(operation: :make_credential, connection: opts[:connection]))
        end

        public_class_method def self.get_assertion(opts = {})
          perform(opts.merge(operation: :get_assertion, connection: opts[:connection]))
        end

        public_class_method def self.u2f_register(opts = {})
          perform(opts.merge(operation: :u2f_register, connection: opts[:connection]))
        end

        public_class_method def self.u2f_authenticate(opts = {})
          perform(opts.merge(operation: :u2f_authenticate, connection: opts[:connection]))
        end

        public_class_method def self.authors
          "AUTHOR(S):\n0day Inc. <request.pentest@0dayinc.com>"
        end

        public_class_method def self.help
          puts <<~HELP
            Purpose: Execute native FIDO management without subprocesses or PIN retries.
              #{self}.execute(args: 'optional - Nonsecret argv after fido, or a local help group', connection: 'optional - Transport connection, required for device operations', confirm: 'optional - Literal true required for authentication and mutations', pin: 'optional - Current PIN in memory only', new_pin: 'optional - Replacement PIN in memory only', secret_provider: 'optional - Callable receiving pin or new_pin Symbol when required', timeout: 'optional - Positive finite total operation seconds, default 30', on_keepalive: 'optional - Callable receiving status; exceptions cancel', cancelled: 'optional - Callable returning true to cancel before a command or on keepalive')
            Purpose: Invoke typed CTAP operations with caller-owned RP and origin policy.
              #{self}.perform(operation: 'required - Symbol from operations or typed operational API', connection: 'required - Transport connection', confirm: 'optional - Literal true required for authentication and mutations')
            Purpose: Create a credential from caller-supplied clientDataHash and RP/user entities.
              #{self}.make_credential(connection: 'required - Transport connection', client_data_hash: 'required - Binary 32-byte SHA-256 digest of caller-created clientDataJSON', rp: 'required - Text-keyed relying-party entity with id', user: 'required - Text-keyed user entity with binary id', confirm: 'required - Literal true for credential creation')
            Purpose: Obtain every assertion advertised by the authenticator for a caller-supplied RP.
              #{self}.get_assertion(connection: 'required - Transport connection', rp_id: 'required - Exact relying-party ID', client_data_hash: 'required - Binary 32-byte caller-provided clientDataJSON digest', confirm: 'required - Literal true for signing and counters')
            Purpose: Register a U2F credential without inventing an application or client identity.
              #{self}.u2f_register(connection: 'required - Transport connection', client_data_hash: 'required - Binary 32-byte caller-provided clientData digest', app_id_hash: 'required - Binary 32-byte application parameter', confirm: 'required - Literal true for credential creation')
            Purpose: Authenticate a U2F key handle or perform an explicit check-only request.
              #{self}.u2f_authenticate(connection: 'required - Transport connection', client_data_hash: 'required - Binary 32-byte caller-provided clientData digest', app_id_hash: 'required - Binary 32-byte application parameter', key_handle: 'required - Binary U2F credential handle', check_only: 'optional - Literal boolean, default false', confirm: 'required - Literal true for authentication')
            Purpose: List implemented management leaf paths, excluding local help groups.
              #{self}.operations
            Purpose: Encode bounded canonical CTAP CBOR using binary versus UTF-8 String tags.
              #{self}::CBOR.encode(value: 'required - Supported CBOR value, binary Strings encode byte strings')
            Purpose: Decode one complete canonical CTAP CBOR object with resource limits.
              #{self}::CBOR.decode(data: 'required - Raw binary CBOR String')
            Purpose: Identify the implementation authors.
              #{self}.authors
            PINs, tokens and key agreements are not persisted or returned by management calls.
            See the paired skill for typed operation options and relying-party responsibilities.
          HELP
        end

        # One operation per session. The connection is caller-owned and remains open.
        class Session # rubocop:disable Metrics/ClassLength
          def initialize(opts)
            @opts = opts.dup
            @connection = opts[:connection]
            raise ArgumentError, 'FIDO requires a connection' unless @connection.respond_to?(:exchange) && @connection.respond_to?(:descriptor)

            timeout = opts.fetch(:timeout, 30)
            raise ArgumentError, 'FIDO timeout must be positive and finite' unless timeout.is_a?(Numeric) && timeout.real? && timeout.finite? && timeout.positive?

            @deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
            @secrets = []
            @max_message = 1024
            @descriptor = @connection.descriptor
            raise ArgumentError, 'FIDO requires CTAP HID or APDU transport' unless %i[ctap apdu].include?(@descriptor[:protocol])

            %i[cancelled on_keepalive secret_provider].each do |key|
              raise ArgumentError, "#{key} must be callable" if !opts[key].nil? && !opts[key].respond_to?(:call)
            end
            %i[u2f uv csv check_only].each do |key|
              raise ArgumentError, "#{key} must be boolean" if opts.key?(key) && ![true, false].include?(opts[key])
            end
          end

          def inspect
            '#<FIDO::Session secrets=redacted>'
          end

          def run(operation)
            confirm! unless %i[info pin_retries bio_sensor_info].include?(operation)
            record_limit if @opts.key?(:max_records)
            public_send(operation)
          end

          def forget
            @secrets.each { |secret| secret.replace("\x00".b * secret.bytesize) unless secret.frozen? }
            @secrets.clear
            @opts.clear
            :forgotten
          end

          def info
            return @info if @info

            caps = @descriptor[:capabilities]
            return u2f_info if caps.is_a?(Integer) && caps.nobits?(4)

            data = ctap(4)
            raise ResponseError, 'Invalid authenticator getInfo versions' unless data[1].is_a?(Array) && !data[1].empty? && data[1].all?(String)
            raise ResponseError, 'Invalid authenticator getInfo options' unless data.fetch(4, {}).is_a?(Hash)
            raise ResponseError, 'Authenticator options must be text-keyed booleans' unless data.fetch(4, {}).all? { |key, value| key.is_a?(String) && key.encoding == Encoding::UTF_8 && [true, false].include?(value) }

            { 13 => 4..255, 16 => 0..1024, 29 => 4..255 }.each do |field, range|
              raise ResponseError, 'Invalid authenticator PIN policy limit' if data.key?(field) && (!data[field].is_a?(Integer) || !range.cover?(data[field]))
            end
            raise ResponseError, 'Invalid authenticator AAGUID' unless data[3].is_a?(String) && data[3].encoding == Encoding::BINARY && data[3].bytesize == 16

            @max_message = data.fetch(5, 1024)
            raise ResponseError, 'Invalid authenticator message limit' unless @max_message.is_a?(Integer) && @max_message.between?(64, CBOR::MAX_BYTES)

            @info = { versions: data[1], ctap2: true, options: data.fetch(4, {}), aaguid: data[3], pin_uv_protocols: data.fetch(6, []), max_message_size: @max_message, raw: data }
          rescue CTAPError => e
            raise unless e.code == 1

            u2f_info
          rescue APDUError => e
            raise unless [0x6d00, 0x6a81].include?(e.code)

            u2f_info
          rescue CommandError
            # CTAPHID INIT can populate capability bits only during the first exchange.
            caps = @connection.descriptor[:capabilities]
            raise unless caps.is_a?(Integer) && caps.nobits?(4)

            u2f_info
          end

          def reset
            if info[:ctap2]
              ctap(7)
            else
              fips_status
              u2f_apdu(0x45)
            end
            { reset: true }
          end

          def pin_retries
            protocol = pin_protocol
            pin = ctap(6, { 1 => protocol.version, 2 => 1 })
            result = { pin_retries: pin[3], power_cycle_state: pin[4] }
            result[:uv_retries] = ctap(6, { 1 => protocol.version, 2 => 7 })[5] if info[:options]['uv']
            result
          end

          def change_pin
            return fips_change_pin if @opts[:u2f] == true || !info[:ctap2]

            protocol = pin_protocol
            minimum = info[:raw].fetch(13, 4)
            maximum = info[:raw].fetch(29, 63)
            new_pin = pin_text(:new_pin, minimum: minimum, maximum: maximum)
            initialized = info[:options]['clientPin'] == false
            raise ArgumentError, 'Authenticator has no current PIN; omit pin when initializing' if initialized && !@opts[:pin].nil?

            old_pin = pin_text(:pin) unless initialized
            length = [64, ((new_pin.bytesize + 15) / 16) * 16].max
            raise ArgumentError, 'Padded PIN exceeds the CTAP 255-byte limit' if length > 255

            local, shared = key_agreement(protocol)
            padded = keep_secret(new_pin.b.ljust(length, "\x00".b))
            new_enc = protocol.encrypt(shared, padded)
            params = { 1 => protocol.version, 2 => initialized ? 3 : 4, 3 => local, 5 => new_enc }
            params[6] = protocol.encrypt(shared, keep_secret(OpenSSL::Digest::SHA256.digest(old_pin).byteslice(0, 16))) unless initialized
            params[4] = protocol.authenticate(shared, new_enc + params.fetch(6, ''.b))
            ctap(6, params)
            { changed: true, initialized: initialized }
          end

          def verify_pin
            raise ArgumentError, 'verify-pin requires a PIN, not built-in UV' if @opts[:uv] == true

            rp_id = text(@opts[:rp_id], 'RP ID', max: 253) if @opts.key?(:rp_id)
            if info[:ctap2]
              permission = if rp_id
                             2
                           elsif info[:options]['credMgmt'] || info[:options]['credentialMgmtPreview']
                             4
                           elsif info[:options].key?('bioEnroll') || info[:options].key?('userVerificationMgmtPreview')
                             8
                           elsif info[:options]['authnrCfg']
                             32
                           end
              authorize(permission, rp_id)
            else
              fips_status
              u2f_apdu(0x43, pin_text(:pin, minimum: 6, maximum: 32).b)
            end
            { verified: true }
          end

          def list_credentials
            command = credential_command
            auth = authorize(4)
            metadata = credential_call(command, 1, nil, auth)
            existing = bounded_count(metadata[1], zero: true)
            rps = enumerate(command, [2, 3], nil, 5, auth)
            credentials = []
            seen_rps = {}
            seen_credentials = {}
            rps.each do |rp|
              hash = binary(rp[4], 'RP ID hash', length: 32, error: ResponseError)
              raise ResponseError, 'Invalid or duplicate RP enumeration' unless rp[3].is_a?(Hash) && rp[3]['id'].is_a?(String) && !seen_rps[hash]

              seen_rps[hash] = true
              enumerate(command, [4, 5], { 1 => hash }, 9, auth).each do |entry|
                descriptor = credential_descriptor(entry[7], error: ResponseError)
                raise ResponseError, 'Duplicate credential in enumeration' if seen_credentials[descriptor['id']]
                raise ResponseError, 'Invalid credential metadata' unless entry[6].is_a?(Hash) && entry[8].is_a?(Hash)

                seen_credentials[descriptor['id']] = true
                credentials << { relying_party: rp[3], rp_id_hash: hash, user: entry[6], credential: descriptor, public_key: entry[8], credential_protection: entry[10], raw: entry }
                raise ResponseError, 'Credential enumeration count limit exceeded' if credentials.size > record_limit
              end
            end
            raise ResponseError, 'Credential enumeration count disagrees with metadata' unless credentials.size == existing

            result = { metadata: { existing: existing, remaining: metadata[2] }, relying_parties: rps.map { |rp| { relying_party: rp[3], rp_id_hash: rp[4] } }, credentials: credentials }
            return result unless @opts[:csv] == true

            require 'csv'
            CSV.generate do |csv|
              csv << %w[credential_id rp_id user_id user_name display_name]
              credentials.each { |entry| csv << [entry[:credential]['id'].unpack1('H*'), entry[:relying_party]['id'], entry[:user]['id']&.unpack1('H*'), entry[:user]['name'], entry[:user]['displayName']] }
            end
          end

          def delete_credential
            descriptor = { 'id' => identifier(:credential_id), 'type' => 'public-key' }
            command = credential_command
            credential_call(command, 6, { 2 => descriptor }, authorize(4))
            { deleted: true }
          end

          def update_credential
            descriptor = { 'id' => identifier(:credential_id), 'type' => 'public-key' }
            user = user_entity(@opts[:user])
            command = credential_command
            raise UnsupportedError, 'Credential user update is not in the preview protocol' unless command == 10

            credential_call(command, 7, { 2 => descriptor, 3 => user }, authorize(4))
            { updated: true }
          end

          def force_change
            require_option!('setMinPINLength')
            raise UnsupportedError, 'Force PIN change requires a configured PIN' unless info[:options]['clientPin'] == true

            configure(3, { 3 => true })
          end

          def set_min_length
            length = integer_option(@opts[:min_length], 'min_length', 4..255)
            rps = @opts[:rp_ids]
            raise ArgumentError, 'rp_ids must be an Array' unless rps.nil? || rps.is_a?(Array)

            rps = rps.map { |rp| text(rp, 'RP ID', max: 253) } if rps
            require_option!('setMinPINLength')
            maximum = info[:raw].fetch(29, 63)
            minimum = info[:raw].fetch(13, 4)
            raise ArgumentError, 'PIN minimum cannot decrease or exceed authenticator maximum' unless length.between?(minimum, maximum)
            raise ArgumentError, 'Too many minimum-PIN-length RP IDs' if rps && rps.size > info[:raw].fetch(16, 0)

            params = { 1 => length, 3 => false }
            params[2] = rps if rps
            configure(3, params)
          end

          def toggle_always_uv
            require_option!('alwaysUv', present: true)
            configure(2)
          end

          def enable_enterprise_attestation
            require_option!('ep', present: true)
            configure(1)
          end

          def bio_sensor_info
            command = bio_command
            modality = ctap(command, { 6 => true })[1]
            raise UnsupportedError, 'Authenticator biometric modality is not fingerprint' unless modality == 1

            result = bio_call(command, 7)
            { modality: modality, fingerprint_kind: result[2], max_samples: result[3], max_name_bytes: result.fetch(8, 64), raw: result }
          end

          def list_fingerprints
            command = bio_command
            bio_sensor_info
            auth = authorize(8)
            templates = begin
              bio_call(command, 4, nil, auth)[7]
            rescue CTAPError => e
              raise unless e.code == 0x2c

              []
            end
            raise ResponseError, 'Invalid fingerprint template list' unless templates.is_a?(Array) && templates.size <= record_limit

            seen = {}
            templates.map do |entry|
              raise ResponseError, 'Invalid fingerprint template' unless entry.is_a?(Hash)

              id = binary(entry[1], 'fingerprint template ID', error: ResponseError)
              raise ResponseError, 'Duplicate fingerprint template ID' if seen[id]
              raise ResponseError, 'Invalid fingerprint name' unless entry[2].nil? || (entry[2].is_a?(String) && entry[2].encoding == Encoding::UTF_8)

              seen[id] = true
              { template_id: id, name: entry[2] }
            end
          end

          def rename_fingerprint
            id = identifier(:template_id)
            name = text(@opts[:name], 'fingerprint name')
            command = bio_command
            max_name = bio_sensor_info[:max_name_bytes]
            raise ArgumentError, 'Fingerprint name exceeds sensor limit' if name.bytesize > max_name

            bio_call(command, 5, { 1 => id, 2 => name }, authorize(8))
            { renamed: true }
          end

          def delete_fingerprint
            id = identifier(:template_id)
            command = bio_command
            bio_sensor_info
            bio_call(command, 6, { 1 => id }, authorize(8))
            { deleted: true }
          end

          def cancel_enrollment
            bio_call(bio_command, 3)
            { cancelled: true }
          end

          def add_fingerprint
            name = text(@opts[:name], 'fingerprint name') if @opts[:name]
            timeout_ms = integer_option(@opts.fetch(:capture_timeout_ms, 10_000), 'capture_timeout_ms', 1..120_000)
            max_samples = integer_option(@opts.fetch(:max_samples, 128), 'max_samples', 1..1024)
            callback = @opts[:on_sample]
            raise ArgumentError, 'on_sample must be callable' if callback && !callback.respond_to?(:call)

            command = bio_command
            sensor = bio_sensor_info
            raise ArgumentError, 'Fingerprint name exceeds sensor limit' if name && name.bytesize > sensor[:max_name_bytes]

            auth = authorize(8)
            pending = true
            response = bio_call(command, 1, { 3 => timeout_ms }, auth)
            id = binary(response[4], 'fingerprint template ID', error: ResponseError)
            max_samples.times do |index|
              status = response[5]
              remaining_samples = response[6]
              raise ResponseError, 'Invalid fingerprint capture status' unless status.is_a?(Integer) && status.between?(0, 14)
              raise ResponseError, 'Invalid fingerprint remaining-sample count' unless remaining_samples.is_a?(Integer) && remaining_samples.between?(0, 1024)

              complete = status.zero? && remaining_samples.zero?
              pending = false if complete
              callback&.call({ template_id: id, status: status, remaining_samples: remaining_samples })
              if complete
                if name
                  begin
                    bio_call(command, 5, { 1 => id, 2 => name }, auth)
                  rescue Error
                    raise EnrollmentError, id
                  end
                end
                return { enrolled: true, template_id: id, name: name }
              end
              raise ResponseError, 'Fingerprint already enrolled or database full' if [11, 12].include?(status)
              raise TimeoutError, 'Fingerprint sample limit exceeded; enrollment cancelled' if index + 1 == max_samples

              response = bio_call(command, 2, { 1 => id, 3 => timeout_ms }, auth)
            end
          ensure
            if pending && command
              begin
                # Cleanup is bounded separately, and must run even if cancelled/deadline expired.
                ctap(command, { 1 => 1, 2 => 3 }, cleanup: true)
              rescue StandardError
                # Preserve the original exception. No retry or credential deletion.
                nil
              end
            end
          end

          def make_credential
            client_hash = binary(@opts[:client_data_hash], 'clientDataHash', length: 32)
            rp = @opts[:rp]
            raise ArgumentError, 'RP must be a caller-supplied entity Hash' unless rp.is_a?(Hash)

            rp_id = text(rp['id'], 'RP ID', max: 253)
            text(rp['name'], 'RP name') if rp.key?('name')
            user = user_entity(@opts[:user])
            key_params = @opts.fetch(:key_params, [{ 'type' => 'public-key', 'alg' => -7 }])
            raise ArgumentError, 'key_params must be public-key algorithm descriptors' unless key_params.is_a?(Array) && key_params.size.between?(1, 64) && key_params.all? { |param| param.is_a?(Hash) && param['type'] == 'public-key' && param['alg'].is_a?(Integer) }

            params = { 1 => client_hash, 2 => rp, 3 => user, 4 => key_params }
            params[5] = credential_list(@opts[:exclude_list]) if @opts.key?(:exclude_list)
            add_request_options(params, 6, 7)
            params[10] = integer_option(@opts[:enterprise_attestation], 'enterprise_attestation', 1..2) if @opts.key?(:enterprise_attestation)
            preflight_request(params)
            require_option!('rk') if params[7]&.fetch('rk', false)
            require_option!('ep') if params[10]
            needs_pin = info[:options]['clientPin'] && !(info[:options]['makeCredUvNotRqd'] && !params[7]&.fetch('rk', false))
            if authentication_requested? || needs_pin
              protocol, token = authorize(1, rp_id)
              params[8] = protocol.authenticate(token, client_hash)
              params[9] = protocol.version
              # UV is performed through the token; CTAP forbids uv=true together with it.
              params[7] = params[7].except('uv') if params[7]
            end
            result = ctap(1, params)
            raise ResponseError, 'Invalid makeCredential response' unless result[1].is_a?(String) && result[3].is_a?(Hash)

            { format: result[1], authenticator_data: authenticator_data(result[2]), attestation_statement: result[3], enterprise_attestation: result[4], large_blob_key: result[5], raw: result }
          end

          def get_assertion # rubocop:disable Naming/AccessorMethodName -- CTAP command name
            rp_id = text(@opts[:rp_id], 'RP ID', max: 253)
            client_hash = binary(@opts[:client_data_hash], 'clientDataHash', length: 32)
            params = { 1 => rp_id, 2 => client_hash }
            params[3] = credential_list(@opts[:allow_list]) if @opts.key?(:allow_list)
            add_request_options(params, 4, 5)
            preflight_request(params)
            if authentication_requested?
              protocol, token = authorize(2, rp_id)
              params[6] = protocol.authenticate(token, client_hash)
              params[7] = protocol.version
              params[5] = params[5].except('uv') if params[5]
            end
            first = ctap(2, params)
            count = bounded_count(first.fetch(5, 1))
            results = [first] + Array.new(count - 1) { ctap(8) }
            results.map do |result|
              credential_descriptor(result[1], error: ResponseError) if result[1]
              { credential: result[1], authenticator_data: authenticator_data(result[2]), signature: binary(result[3], 'assertion signature', error: ResponseError), user: result[4], user_selected: result[6], large_blob_key: result[7], raw: result }
            end
          end

          def u2f_register
            client = binary(@opts[:client_data_hash], 'clientDataHash', length: 32)
            application = binary(@opts[:app_id_hash], 'application hash', length: 32)
            response = u2f_apdu(1, client + application)
            raise ResponseError, 'Invalid U2F registration response' unless response.bytesize > 67 && response.getbyte(0) == 5 && response.getbyte(1) == 4

            key_length = response.getbyte(66)
            raise ResponseError, 'Invalid U2F key handle length' if key_length.zero? || response.bytesize <= 67 + key_length

            cert_offset = 67 + key_length
            certificate_length = der_length(response.byteslice(cert_offset..))
            certificate = response.byteslice(cert_offset, certificate_length)
            OpenSSL::X509::Certificate.new(certificate)
            signature = response.byteslice((cert_offset + certificate_length)..)
            raise ResponseError, 'Missing U2F attestation signature' if signature.nil? || signature.empty?

            { public_key: response.byteslice(1, 65), key_handle: response.byteslice(67, key_length), certificate: certificate, signature: signature, raw: response }
          rescue OpenSSL::OpenSSLError
            raise ResponseError, 'Malformed U2F attestation certificate'
          end

          def u2f_authenticate
            client = binary(@opts[:client_data_hash], 'clientDataHash', length: 32)
            application = binary(@opts[:app_id_hash], 'application hash', length: 32)
            key_handle = binary(@opts[:key_handle], 'U2F key handle', max: 255)
            check = @opts.fetch(:check_only, false)
            raise ArgumentError, 'check_only must be boolean' unless [true, false].include?(check)

            response = u2f_apdu(2, client + application + [key_handle.bytesize].pack('C') + key_handle, check ? 7 : 3)
            raise ResponseError, 'Unexpected successful check-only response' if check
            raise ResponseError, 'Invalid U2F authentication response' unless response.bytesize > 5 && response.getbyte(0).allbits?(1)

            { user_presence: response.getbyte(0), counter: response.byteslice(1, 4).unpack1('N'), signature: response.byteslice(5..), raw: response }
          rescue APDUError => e
            raise unless check && [0x6985, 0x6a80].include?(e.code)

            { recognized: e.code == 0x6985 }
          end

          private

          def credential_list(list)
            raise ArgumentError, 'Credential list must be an Array' unless list.is_a?(Array) && list.size <= record_limit

            list.each { |descriptor| credential_descriptor(descriptor) }
            list
          end

          def add_request_options(params, extensions_key, options_key)
            if @opts.key?(:extensions)
              raise ArgumentError, 'Extensions must be a text-keyed map' unless @opts[:extensions].is_a?(Hash) && @opts[:extensions].keys.all? { |key| key.is_a?(String) && key.encoding == Encoding::UTF_8 }

              params[extensions_key] = @opts[:extensions]
            end
            return unless @opts.key?(:authenticator_options)

            options = @opts[:authenticator_options]
            raise ArgumentError, 'Authenticator options must be a text/boolean map' unless options.is_a?(Hash) && options.all? { |key, value| key.is_a?(String) && key.encoding == Encoding::UTF_8 && [true, false].include?(value) }

            params[options_key] = options
          end

          def preflight_request(params)
            encoded = CBOR.encode(value: params)
            require_ctap2!
            # Reserve space for protocol 2 PIN/UV authentication before requesting a token.
            raise ArgumentError, 'CTAP request exceeds authenticator message limit' if encoded.bytesize + 40 > @max_message
          end

          def authentication_requested?
            !@opts[:pin].nil? || !@opts[:secret_provider].nil? || @opts[:uv] == true
          end

          def authenticator_data(value)
            binary(value, 'authenticator data', max: CBOR::MAX_BYTES, error: ResponseError)
            raise ResponseError, 'Truncated authenticator data' if value.bytesize < 37

            value
          end

          def der_length(data)
            raise ResponseError, 'Malformed DER certificate header' unless data.bytesize >= 2 && data.getbyte(0) == 0x30

            first = data.getbyte(1)
            return 2 + first if first < 128 && data.bytesize >= 2 + first

            width = first & 127
            raise ResponseError, 'Malformed DER certificate length' unless width.between?(1, 4) && data.bytesize >= 2 + width && data.getbyte(2).positive?

            length = data.byteslice(2, width).bytes.reduce(0) { |total, byte| (total << 8) | byte }
            raise ResponseError, 'Truncated or noncanonical DER certificate' unless length >= 128 && length < (1 << (8 * width)) && data.bytesize >= 2 + width + length

            2 + width + length
          end

          def bio_command
            require_ctap2!
            return 9 if info[:options].key?('bioEnroll')
            return 0x40 if info[:versions].include?('FIDO_2_1_PRE') && info[:options].key?('userVerificationMgmtPreview')

            raise UnsupportedError, 'Authenticator lacks biometric enrollment'
          end

          def bio_call(command, subcommand, parameters = nil, auth = nil)
            params = { 1 => 1, 2 => subcommand }
            params[3] = parameters if parameters
            if auth
              protocol, token = auth
              msg = [1, subcommand].pack('CC') + (parameters ? CBOR.encode(value: parameters) : ''.b)
              params[4] = protocol.version
              params[5] = protocol.authenticate(token, msg)
            end
            ctap(command, params)
          end

          def binary(value, label, length: nil, max: 4096, error: ArgumentError)
            raise error, "Invalid #{label}: expected binary String of the required length" unless value.is_a?(String) && value.encoding == Encoding::BINARY && value.bytesize.positive? && value.bytesize <= max && (length.nil? || value.bytesize == length)

            value
          end

          def text(value, label, max: 256)
            raise ArgumentError, "Invalid #{label}: expected nonempty UTF-8 text" unless value.is_a?(String) && value.encoding == Encoding::UTF_8 && value.valid_encoding? && value.bytesize.between?(1, max) && !value.include?("\x00")

            value
          end

          def integer_option(value, label, range)
            value = Integer(value, 10) if value.is_a?(String) && value.match?(/\A[0-9]+\z/)
            raise ArgumentError, "Invalid #{label}" unless value.is_a?(Integer) && range.cover?(value)

            value
          end

          def identifier(name)
            hex = @opts[:"#{name}_hex"]
            if hex
              raise ArgumentError, 'Identifier must be complete, even-length hexadecimal' unless hex.is_a?(String) && hex.match?(/\A(?:[0-9a-fA-F]{2})+\z/) && hex.bytesize <= 8192

              return [hex].pack('H*')
            end
            binary(@opts[name], name)
          end

          def user_entity(user)
            raise ArgumentError, 'User entity must be a Hash' unless user.is_a?(Hash)

            binary(user['id'], 'user ID', max: 64)
            %w[name displayName].each { |field| text(user[field], field, max: 64) if user.key?(field) }
            CBOR.encode(value: user)
            user
          end

          def credential_descriptor(descriptor, error: ArgumentError)
            raise error, 'Invalid public-key credential descriptor' unless descriptor.is_a?(Hash) && descriptor['type'] == 'public-key'

            binary(descriptor['id'], 'credential ID', error: error)
            descriptor
          end

          def record_limit
            integer_option(@opts.fetch(:max_records, 1024), 'max_records', 1..16_384)
          end

          def bounded_count(value, zero: false)
            raise ResponseError, 'Invalid or excessive authenticator count' unless value.is_a?(Integer) && value.between?(zero ? 0 : 1, record_limit)

            value
          end

          def require_option!(name, present: false)
            require_ctap2!
            supported = present ? info[:options].key?(name) : info[:options][name] == true
            raise UnsupportedError, "Authenticator does not support #{name}" unless supported
          end

          def credential_command
            require_ctap2!
            return 10 if info[:options]['credMgmt'] == true
            return 0x41 if info[:versions].include?('FIDO_2_1_PRE') && info[:options].key?('credentialMgmtPreview')

            raise UnsupportedError, 'Authenticator lacks credential management'
          end

          def credential_call(command, subcommand, parameters, auth = nil)
            params = { 1 => subcommand }
            params[2] = parameters unless parameters.nil?
            if auth
              protocol, token = auth
              message = [subcommand].pack('C') + (parameters ? CBOR.encode(value: parameters) : ''.b)
              params[3] = protocol.version
              params[4] = protocol.authenticate(token, message)
            end
            ctap(command, params)
          end

          def enumerate(command, sequence, parameters, total_key, auth)
            begin_command, next_command = sequence
            first = begin
              credential_call(command, begin_command, parameters, auth)
            rescue CTAPError => e
              raise unless e.code == 0x2e

              nil
            end
            return [] unless first

            count = bounded_count(first.fetch(total_key, 1), zero: true)
            return [] if count.zero?

            [first] + Array.new(count - 1) { credential_call(command, next_command, nil) }
          end

          def configure(subcommand, parameters = nil)
            require_option!('authnrCfg')
            allowed = info[:raw][31]
            raise UnsupportedError, 'Configuration subcommand not supported by authenticator' if allowed && !allowed.include?(subcommand)

            params = { 1 => subcommand }
            params[2] = parameters if parameters
            if info[:options]['clientPin'] || @opts[:uv] == true
              protocol, token = authorize(32)
              message = ("\xff".b * 32) + [0x0d, subcommand].pack('CC') + (parameters ? CBOR.encode(value: parameters) : ''.b)
              params[3] = protocol.version
              params[4] = protocol.authenticate(token, message)
            end
            ctap(13, params)
            { configured: true, subcommand: subcommand }
          end

          def confirm!
            raise ConfirmationRequired, 'FIDO authentication or mutation requires literal confirm: true' unless @opts[:confirm] == true
          end

          def remaining
            raise Cancelled, 'FIDO operation cancelled' if @opts[:cancelled]&.call

            seconds = @deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise TimeoutError, 'FIDO operation deadline exceeded; not retried' unless seconds.positive?

            seconds
          end

          def keepalive(status)
            remaining
            @opts[:on_keepalive]&.call(status)
          end

          def ctap(command, params = nil, cleanup: false)
            read_only = command == 4 || (command == 6 && [1, 2, 7].include?(params&.[](2))) || ([9, 0x40].include?(command) && (params&.[](6) == true || params&.[](2) == 7))
            confirm! unless read_only
            data = [command].pack('C') + (params ? CBOR.encode(value: params) : ''.b)
            raise ArgumentError, 'CTAP request exceeds authenticator message limit' if data.bytesize > @max_message

            response = if @descriptor[:protocol] == :apdu
                         nfc_cbor(data, cleanup: cleanup)
                       else
                         @connection.exchange(protocol: :ctap, command: 0x10, data: data, timeout: wire_timeout(cleanup), on_keepalive: cleanup ? nil : method(:keepalive), cancelled: cleanup ? nil : @opts[:cancelled])
                       end
            raise ResponseError, 'Empty or oversized CTAP response' unless response.is_a?(String) && response.bytesize.between?(1, CBOR::MAX_BYTES)
            raise CTAPError, response.getbyte(0) unless response.getbyte(0).zero?
            return {} if response.bytesize == 1

            decoded = CBOR.decode(data: response.byteslice(1..))
            raise ResponseError, 'CTAP response must be a map' unless decoded.is_a?(Hash)

            decoded
          end

          def u2f_apdu(ins, data = ''.b, parameter1 = 0)
            confirm! unless [3, 0x46].include?(ins)
            if @descriptor[:protocol] == :apdu
              select_fido
              body, status = smartcard_message(0, ins, parameter1, data)
              raise APDUError, status unless status == 0x9000

              return body
            end
            caps = @descriptor[:capabilities]
            raise UnsupportedError, 'Authenticator does not support CTAPHID MSG/U2F' if caps.is_a?(Integer) && caps.anybits?(8)

            packet = [0, ins, parameter1, 0, 0, data.bytesize].pack('CCCCCn') + data + "\x00\x00".b
            response = @connection.exchange(protocol: :ctap, command: 3, data: packet, timeout: remaining, on_keepalive: method(:keepalive), cancelled: @opts[:cancelled])
            raise ResponseError, 'Truncated U2F response' unless response.is_a?(String) && response.bytesize.between?(2, CBOR::MAX_BYTES)

            status = response.byteslice(-2, 2).unpack1('n')
            raise APDUError, status unless status == 0x9000

            response.byteslice(0, response.bytesize - 2)
          end

          def u2f_info
            version = u2f_apdu(3)
            raise ResponseError, 'Unexpected U2F version' unless version == 'U2F_V2'

            @info = { versions: ['U2F_V2'], ctap2: false, options: {}, pin_uv_protocols: [], raw: {} }
          end

          def fips_status
            u2f_apdu(0x46)
            :configured
          rescue APDUError => e
            return :unconfigured if e.code == 0x6a81
            raise unless [0x6d00, 0x6e00, 0x6a86].include?(e.code)

            raise UnsupportedError, 'Authenticator does not implement YubiKey 4 FIPS U2F PIN/reset commands'
          end

          def fips_change_pin
            new_pin = pin_text(:new_pin, minimum: 6, maximum: 32)
            state = fips_status
            old_pin = if state == :configured || @opts[:pin]
                        pin_text(:pin, minimum: 6, maximum: 32)
                      else
                        ''.b
                      end
            data = keep_secret([new_pin.bytesize].pack('C') + old_pin.b + new_pin.b)
            u2f_apdu(0x44, data)
            { changed: true, initialized: state == :unconfigured }
          end

          def wire_timeout(cleanup)
            return remaining unless cleanup

            @cleanup_deadline ||= Process.clock_gettime(Process::CLOCK_MONOTONIC) + 2
            seconds = @cleanup_deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
            raise TimeoutError, 'FIDO cancellation cleanup timed out' unless seconds.positive?

            seconds
          end

          def select_fido
            return if @selected

            aid = [0xa0, 0, 0, 6, 0x47, 0x2f, 0, 1].pack('C*')
            _body, status = smartcard_message(0, 0xa4, 4, aid)
            raise APDUError, status unless status == 0x9000

            @selected = true
          end

          def smartcard_message(cla, ins, parameter1, data = ''.b, cleanup: false)
            offset = 0
            while data.bytesize - offset > 250
              chunk = data.byteslice(offset, 250)
              body, status = smartcard_exchange([cla | 0x10, ins, parameter1, 0, 250].pack('C*') + chunk, cleanup: cleanup)
              raise APDUError, status unless status == 0x9000
              raise ResponseError, 'Unexpected response during APDU command chaining' unless body.empty?

              offset += 250
            end
            chunk = data.byteslice(offset..)
            packet = [cla, ins, parameter1, 0].pack('C*')
            packet += [chunk.bytesize].pack('C') + chunk unless chunk.empty?
            body, status = smartcard_exchange(packet + "\x00".b, cleanup: cleanup)
            128.times do
              return [body, status] unless status >> 8 == 0x61

              extra, status = smartcard_exchange([0, 0xc0, 0, 0, status & 255].pack('C*'), cleanup: cleanup)
              body += extra
              raise ResponseError, 'FIDO APDU response limit exceeded' if body.bytesize > CBOR::MAX_BYTES
            end
            raise ResponseError, 'FIDO GET RESPONSE iteration limit exceeded'
          end

          def smartcard_exchange(packet, cleanup: false)
            response = @connection.exchange(protocol: :apdu, data: packet, timeout: wire_timeout(cleanup), cancelled: cleanup ? nil : @opts[:cancelled])
            raise ResponseError, 'Truncated or oversized FIDO APDU' unless response.is_a?(String) && response.bytesize.between?(2, CBOR::MAX_BYTES)

            [response.byteslice(0, response.bytesize - 2), response.byteslice(-2, 2).unpack1('n')]
          end

          def nfc_cbor(data, cleanup: false)
            select_fido
            body, status = smartcard_message(0x80, 0x10, 0x80, data, cleanup: cleanup)
            while status == 0x9100
              pending = true
              raise ResponseError, 'Invalid NFC keepalive status' unless body.bytesize == 1 && [1, 2].include?(body.getbyte(0))

              keepalive(body.getbyte(0)) unless cleanup
              body, status = smartcard_message(0x80, 0x11, 0, cleanup: cleanup)
            end
            pending = false
            raise APDUError, status unless status == 0x9000

            body
          ensure
            if pending
              begin
                smartcard_message(0x80, 0x11, 0x11, cleanup: true)
              rescue StandardError
                nil
              end
            end
          end

          def require_ctap2!
            raise UnsupportedError, 'Authenticator supports U2F only; CTAP2 operation unavailable' unless info[:ctap2]
          end

          def pin_protocol
            require_ctap2!
            raise UnsupportedError, 'Authenticator does not support clientPin' unless info[:options].key?('clientPin') || @opts[:uv] == true

            versions = info[:pin_uv_protocols]
            raise ResponseError, 'Invalid PIN protocol list' unless versions.is_a?(Array)

            version = [2, 1].find { |candidate| versions.include?(candidate) }
            raise UnsupportedError, 'Authenticator has no supported PIN protocol (1 or 2)' unless version

            PinProtocol.new(version)
          end

          def keep_secret(bytes)
            @secrets << bytes
            bytes
          end

          def pin_text(name, minimum: 4, maximum: 63)
            confirm!
            value = @opts[name]
            value = @opts[:secret_provider].call(name) if value.nil? && @opts[:secret_provider]
            raise ArgumentError, "#{name} must be supplied in memory" unless value.is_a?(String)

            text = value.dup.force_encoding(Encoding::UTF_8)
            raise ArgumentError, "#{name} has invalid UTF-8, length or NUL character" unless text.valid_encoding? && text.length >= minimum && text.bytesize <= maximum && !text.include?("\x00")

            keep_secret(text)
          end

          def key_agreement(protocol)
            peer = ctap(6, { 1 => protocol.version, 2 => 2 })[1]
            local, shared = protocol.encapsulate(peer)
            [local, keep_secret(shared)]
          end

          def authorize(permissions, rp_id = nil)
            confirm!
            protocol = pin_protocol
            using_uv = @opts[:uv] == true
            raise UnsupportedError, 'UV tokens require configured built-in UV, permissions and pinUvAuthToken support' if using_uv && (!info[:options]['uv'] || !info[:options]['pinUvAuthToken'] || permissions.nil?)

            pin = pin_text(:pin) unless using_uv
            raise UnsupportedError, 'Authenticator has no configured client PIN' if !using_uv && info[:options]['clientPin'] != true

            local, shared = key_agreement(protocol)
            scoped = !permissions.nil? && info[:options]['pinUvAuthToken'] == true
            params = { 1 => protocol.version, 2 => if using_uv
                                                     6
                                                   else
                                                     (scoped ? 9 : 5)
                                                   end, 3 => local }
            params[6] = protocol.encrypt(shared, keep_secret(OpenSSL::Digest::SHA256.digest(pin).byteslice(0, 16))) unless using_uv
            if scoped
              params[9] = permissions
              params[10] = rp_id if rp_id
            end
            encrypted = ctap(6, params)[2]
            token = keep_secret(protocol.validate_token(protocol.decrypt(shared, encrypted)))
            [protocol, token]
          end
        end

        # Ephemeral key agreement and CTAP PIN/UV protocols 1 and 2.
        # Keys are generated with OpenSSL's OS-seeded CSPRNG, never device OTP.
        class PinProtocol
          attr_reader :version

          def initialize(version)
            raise ArgumentError, 'PIN protocol must be 1 or 2' unless [1, 2].include?(version)

            @version = version
          end

          def derive(shared_x)
            raise ResponseError, 'Invalid ECDH secret length' unless shared_x.is_a?(String) && shared_x.bytesize == 32
            return OpenSSL::Digest::SHA256.digest(shared_x) if @version == 1

            # HKDF-Extract followed by one HKDF-Expand block for each label.
            prk = OpenSSL::HMAC.digest('SHA256', "\x00".b * 32, shared_x)
            ['CTAP2 HMAC key', 'CTAP2 AES key'].map { |info| OpenSSL::HMAC.digest('SHA256', prk, info.b + "\x01".b) }.join.b
          end

          def encapsulate(peer)
            raise ResponseError, 'Invalid PIN key agreement COSE key' unless peer.is_a?(Hash) && peer[1] == 2 && peer[3] == -25 && peer[-1] == 1 && [-2, -3].all? { |label| peer[label].is_a?(String) && peer[label].encoding == Encoding::BINARY && peer[label].bytesize == 32 }

            group = OpenSSL::PKey::EC::Group.new('prime256v1')
            point = OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new("\x04".b + peer[-2] + peer[-3], 2))
            raise ResponseError, 'Invalid PIN key agreement point' if point.infinity? || !point.on_curve?

            ephemeral = OpenSSL::PKey::EC.generate('prime256v1')
            public_bytes = ephemeral.public_key.to_octet_string(:uncompressed)
            local = { 1 => 2, 3 => -25, -1 => 1, -2 => public_bytes.byteslice(1, 32), -3 => public_bytes.byteslice(33, 32) }
            [local, derive(ephemeral.dh_compute_key(point))]
          rescue OpenSSL::OpenSSLError, ArgumentError
            raise ResponseError, 'Invalid PIN key agreement point'
          end

          def authenticate(key, message)
            mac = OpenSSL::HMAC.digest('SHA256', @version == 1 ? key : key.byteslice(0, 32), message)
            @version == 1 ? mac.byteslice(0, 16) : mac
          end

          def encrypt(key, plaintext)
            validate_cipher_input(key, plaintext, ArgumentError)
            iv = @version == 1 ? "\x00".b * 16 : SecureRandom.random_bytes(16)
            output = cipher(key, iv, plaintext, true)
            @version == 1 ? output : iv + output
          end

          def decrypt(key, ciphertext)
            if @version == 2
              raise ResponseError, 'Truncated protocol 2 ciphertext' unless ciphertext.is_a?(String) && ciphertext.bytesize >= 32

              iv = ciphertext.byteslice(0, 16)
              ciphertext = ciphertext.byteslice(16..)
            else
              iv = "\x00".b * 16
            end
            validate_cipher_input(key, ciphertext, ResponseError)
            cipher(key, iv, ciphertext, false)
          end

          def validate_token(token)
            sizes = @version == 1 ? [16, 32] : [32]
            raise ResponseError, 'Invalid PIN/UV token length' unless token.is_a?(String) && sizes.include?(token.bytesize)

            token
          end

          private

          def validate_cipher_input(key, data, error)
            raise error, 'Invalid PIN cipher key length' unless key.is_a?(String) && key.bytesize == (@version == 1 ? 32 : 64)
            raise error, 'Invalid PIN cipher block length' unless data.is_a?(String) && data.bytesize.positive? && (data.bytesize % 16).zero?
          end

          def cipher(key, iv_bytes, data, encrypt)
            aes = OpenSSL::Cipher.new('aes-256-cbc')
            encrypt ? aes.encrypt : aes.decrypt
            aes.padding = 0
            aes.key = @version == 1 ? key : key.byteslice(32, 32)
            aes.iv = iv_bytes
            aes.update(data) + aes.final
          end
        end

        # CTAP canonical CBOR: binary Strings are bytes, UTF-8 Strings are text.
        # Reject indefinite lengths, tags/floats, duplicates and excessive work.
        module CBOR
          MAX_BYTES = 1_048_576
          MAX_ITEMS = 16_384
          MAX_DEPTH = 32

          public_class_method def self.encode(opts = {})
            Codec.new.encode(opts[:value])
          end

          public_class_method def self.decode(opts = {})
            Codec.new.decode(opts[:data])
          end

          public_class_method def self.authors
            "AUTHOR(S):\n0day Inc. <request.pentest@0dayinc.com>"
          end

          public_class_method def self.help
            puts <<~HELP
              Purpose: Encode bounded CTAP canonical CBOR without a runtime dependency.
                #{self}.encode(value: 'required - Integer, binary or UTF-8 String, Array, Hash, boolean or nil')
              Purpose: Decode exactly one bounded canonical CBOR object.
                #{self}.decode(data: 'required - Binary CBOR String')
              Purpose: Identify the implementation authors.
                #{self}.authors
            HELP
          end

          # Per-call budget prevents recursion and allocation attacks in either direction.
          class Codec
            def initialize
              @items = 0
              @encoded_size = 0
            end

            def encode(value, depth = 0)
              budget(depth, ArgumentError)
              out = case value
                    when Integer then header(value.negative? ? 1 : 0, value.negative? ? -1 - value : value)
                    when String
                      binary = value.encoding == Encoding::BINARY
                      text = binary ? value : value.encode(Encoding::UTF_8)
                      raise ArgumentError, 'CBOR text must be valid UTF-8' unless text.valid_encoding?
                      raise ArgumentError, 'CBOR byte limit exceeded' if text.bytesize > MAX_BYTES

                      header(binary ? 2 : 3, text.bytesize) + text.b
                    when Array
                      raise ArgumentError, 'CBOR item limit exceeded' if value.size > MAX_ITEMS

                      header(4, value.size) + value.map { |entry| encode(entry, depth + 1) }.join.b
                    when Hash
                      raise ArgumentError, 'CBOR item limit exceeded' if value.size > MAX_ITEMS

                      entries = value.map do |key, entry|
                        validate_key(key, ArgumentError)
                        [encode(key, depth + 1), encode(entry, depth + 1)]
                      end
                      header(5, entries.size) + entries.sort_by { |key, _| [key.getbyte(0), key.bytesize, key] }.join.b
                    when true then "\xf5".b
                    when false then "\xf4".b
                    when nil then "\xf6".b
                    else raise ArgumentError, 'Unsupported CBOR type'
                    end
              # Count leaf data once; every assembled container is also bounded.
              @encoded_size += out.bytesize unless value.is_a?(Array) || value.is_a?(Hash)
              raise ArgumentError, 'CBOR byte limit exceeded' if out.bytesize > MAX_BYTES || @encoded_size > MAX_BYTES

              out
            rescue EncodingError
              raise ArgumentError, 'CBOR text must be valid UTF-8'
            end

            def decode(data)
              raise ResponseError, 'CBOR requires a bounded binary String' unless data.is_a?(String) && data.bytesize <= MAX_BYTES

              @data = data.b
              @offset = 0
              value = read_value(0)
              raise ResponseError, 'Trailing CBOR bytes' unless @offset == @data.bytesize

              value
            end

            private

            def header(major, value)
              raise ArgumentError, 'CBOR integer out of range' unless value.between?(0, 0xffffffffffffffff)

              case value
              when 0..23 then [(major << 5) | value].pack('C')
              when 24..255 then [(major << 5) | 24, value].pack('CC')
              when 256..65_535 then [(major << 5) | 25, value].pack('Cn')
              when 65_536..0xffffffff then [(major << 5) | 26, value].pack('CN')
              else [(major << 5) | 27, value].pack('CQ>')
              end
            end

            def budget(depth, error)
              @items += 1
              raise error, 'CBOR depth limit exceeded (possibly cyclic input)' if depth > MAX_DEPTH
              raise error, 'CBOR item limit exceeded' if @items > MAX_ITEMS
            end

            def validate_key(key, error)
              return if key.is_a?(Integer) || (key.is_a?(String) && key.encoding == Encoding::UTF_8)

              raise error, 'CTAP CBOR map keys must be integers or text'
            end

            def take(length)
              raise ResponseError, 'Truncated CBOR' if length > @data.bytesize - @offset

              result = @data.byteslice(@offset, length)
              @offset += length
              result
            end

            def length_value(additional_info)
              return additional_info if additional_info < 24

              width, fmt, minimum = { 24 => [1, 'C', 24], 25 => [2, 'n', 256], 26 => [4, 'N', 65_536], 27 => [8, 'Q>', 0x100000000] }[additional_info]
              raise ResponseError, 'Indefinite or invalid CBOR length' unless width

              value = take(width).unpack1(fmt)
              raise ResponseError, 'Noncanonical CBOR integer or length' if value < minimum

              value
            end

            def read_value(depth)
              budget(depth, ResponseError)
              first = take(1).getbyte(0)
              major = first >> 5
              ai = first & 31
              return { 20 => false, 21 => true, 22 => nil }.fetch(ai) { raise ResponseError, 'Unsupported CBOR simple/float value' } if major == 7

              length = length_value(ai)
              case major
              when 0 then length
              when 1 then -1 - length
              when 2, 3
                raise ResponseError, 'CBOR byte limit exceeded' if length > MAX_BYTES

                value = take(length)
                value.force_encoding(Encoding::UTF_8) if major == 3
                raise ResponseError, 'Invalid CBOR UTF-8' unless value.valid_encoding?

                value
              when 4, 5
                raise ResponseError, 'CBOR item limit exceeded' if length > MAX_ITEMS
                return Array.new(length) { read_value(depth + 1) } if major == 4

                map = {}
                previous = nil
                length.times do
                  start = @offset
                  key = read_value(depth + 1)
                  validate_key(key, ResponseError)
                  encoded = @data.byteslice(start, @offset - start)
                  order = [encoded.getbyte(0), encoded.bytesize, encoded]
                  raise ResponseError, 'Noncanonical CBOR map ordering or duplicate key' if previous && (previous <=> order) >= 0
                  raise ResponseError, 'Duplicate CBOR map key' if map.key?(key)

                  previous = order
                  map[key] = read_value(depth + 1)
                end
                map
              else raise ResponseError, 'Unsupported CBOR tag/type'
              end
            end
          end
        end
      end
    end
  end
end
