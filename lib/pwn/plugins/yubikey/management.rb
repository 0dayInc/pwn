# frozen_string_literal: true

require 'securerandom'
require 'pwn/plugins/yubikey/protocol'

module PWN
  module Plugins
    module YubiKey
      # Native device configuration, capabilities and legacy USB mode protocol.
      # Reference: Yubico yubikit.management 5.9.1 (wire-format specification).
      module Management
        AID = ['a000000527471117'].pack('H*').freeze
        OTP_AID = ['a0000005272001'].pack('H*').freeze
        CAPABILITIES = { 'OTP' => 0x01, 'U2F' => 0x02, 'OPENPGP' => 0x08, 'PIV' => 0x10, 'OATH' => 0x20, 'HSMAUTH' => 0x100, 'FIDO2' => 0x200 }.freeze
        MODES = [1, 4, 5, 2, 3, 6, 7].freeze

        public_class_method def self.info(opts = {})
          session = begin_session(connection: opts[:connection], timeout: opts.fetch(:timeout, 30))
          read_information(session: session)
        end

        GRAMMAR = {
          'usb' => [0, %w[--force --list --enable-all --touch-eject --no-touch-eject], %w[--enable --disable --autoeject-timeout --chalresp-timeout]],
          'nfc' => [0, %w[--force --list --enable-all --disable-all --restrict], %w[--enable --disable]],
          'mode' => [1, %w[--force --touch-eject], %w[--autoeject-timeout --chalresp-timeout]],
          'set-lock-code' => [0, %w[--force --clear --generate], []],
          'reset' => [0, %w[--force], []]
        }.freeze
        ROUTES = { 'usb' => :configure_usb, 'nfc' => :configure_nfc, 'mode' => :set_mode, 'set-lock-code' => :set_lock_code, 'reset' => :reset }.freeze

        public_class_method def self.operations(opts = {})
          opts[:format]
          GRAMMAR.keys
        end

        public_class_method def self.execute(opts = {})
          args = opts[:args] || []
          raise ArgumentError, 'args must be an Array of nonsecret Strings' unless args.is_a?(Array) && args.all?(String)
          return { application: :management, operations: operations, secrets: :in_memory_only } if args.empty? || args == ['--help']

          grammar = GRAMMAR[args.first]
          raise ArgumentError, 'Unknown device configuration operation' unless grammar

          parsed = Protocol.parse_args(args: args.drop(1), flags: grammar[1], values: grammar[2])
          raise ArgumentError, 'Invalid management positional argument count' unless parsed[:positionals].length == grammar[0]
          raise ArgumentError, 'Only enable and disable options can be repeated' if parsed[:options].any? { |key, value| value.is_a?(Array) && !%i[enable disable].include?(key) }

          selected = opts.merge(parsed[:options])
          selected[:mode] = parsed[:positionals].first if args.first == 'mode'
          public_send(ROUTES.fetch(args.first), selected)
        end

        public_class_method def self.configure_nfc(opts = {})
          configure_applications(opts.merge(transport: :nfc, connection: opts[:connection]))
        end

        public_class_method def self.set_lock_code(opts = {})
          consent(opts.merge(confirm: opts[:confirm]))
          choices = [opts[:clear], opts[:generate], !opts[:new_lock_code].nil?].count { |value| value }
          raise ArgumentError, 'Specify only one of clear, generate or new_lock_code' if choices > 1

          code = if opts[:clear]
                   "\0".b * 16
                 elsif opts[:generate]
                   raise ArgumentError, 'Generated lock code requires an explicit secret_sink callable' unless opts[:secret_sink].respond_to?(:call)

                   value = SecureRandom.random_bytes(16)
                   opts[:secret_sink].call(:new_lock_code, value.dup)
                   value
                 else
                   secret_value(opts.merge(value: opts[:new_lock_code], name: :new_lock_code))
                 end
          raise ArgumentError, 'new_lock_code must contain exactly 16 raw bytes' unless code.bytesize == 16

          session = begin_session(opts)
          before = read_information(session: session)
          require_version(version: before[:version], minimum: [5, 0, 0])
          write_settings(opts.merge(session: session, before: before, changes: { 0x0a => code }, reboot: false))
        end

        public_class_method def self.configure_usb(opts = {})
          configure_applications(opts.merge(transport: :usb, connection: opts[:connection]))
        end

        public_class_method def self.set_mode(opts = {})
          consent(opts.merge(confirm: opts[:confirm]))
          chalresp = numeric(value: opts.fetch(:chalresp_timeout, 0), maximum: 255)
          autoeject = numeric(value: opts.fetch(:autoeject_timeout, 0), maximum: 65_535)
          session = begin_session(opts)
          before = read_information(session: session)
          require_version(version: before[:version], minimum: [3, 0, 0])
          current = before[:enabled_capabilities][:usb] ? interfaces(mask: before[:enabled_capabilities][:usb]) : before[:usb_interfaces]
          requested = parse_mode(value: opts[:mode], current: current)
          eject = opts[:touch_eject] || autoeject.positive?
          raise ArgumentError, 'Touch eject requires CCID-only mode' if eject && requested != 4

          if (before[:version] <=> [5, 0, 0]) >= 0
            supported = before[:supported_capabilities][:usb]
            raise CommandError, 'Requested USB interface is not supported' unless requested.nobits?(~interfaces(mask: supported))
            raise CommandError, 'Applications can only be toggled on this device after reset' if before[:reset_blocked].positive?

            desired = 0
            desired |= 1 if requested.anybits?(1)
            desired |= 0x202 if requested.anybits?(2)
            desired |= 0x538 if requested.anybits?(4)
            changes = { 3 => [desired & supported].pack('n') }
            changes[7] = [chalresp].pack('C') if opts.key?(:chalresp_timeout)
            changes[6] = [autoeject].pack('n') if opts.key?(:autoeject_timeout)
            changes[8] = [before[:device_flags].to_i | 0x80].pack('C') if eject
            write_settings(opts.merge(session: session, before: before, changes: changes, reboot: opts.fetch(:reboot, current != requested)))
          else
            raise ArgumentError, 'Legacy mode changes require reconnect after physical reinsertion for verification' unless opts[:reconnect].respond_to?(:call)
            raise CommandError, 'Requested USB interface is not supported' if before[:supported_capabilities][:usb] && requested.anybits?(~interfaces(mask: before[:supported_capabilities][:usb]))

            code = MODES.index(requested) | (eject ? 0x80 : 0)
            begin
              request(session: session, operation: :mode, data: [code, chalresp, autoeject].pack('CCv'))
              fresh = opts[:reconnect].call(before.except(:raw_fields))
              raise ResponseError, 'Legacy mode readback requires a fresh connection' if fresh.equal?(opts[:connection])

              after = info(connection: fresh, timeout: opts.fetch(:timeout, 30))
              verify_identity(before: before, after: after, reconnected: true)
              raise ResponseError, 'Legacy USB mode readback mismatch' unless after[:usb_interfaces] == requested

              { verified: true, verification: :usb_descriptor, usb_interfaces: requested, info: after, timeouts_readback: false }
            rescue StandardError
              raise ResponseError, 'Legacy mode write state uncertain: reinsert and inspect the exact device; do not replay', cause: nil
            ensure
              fresh.close if fresh && !fresh.equal?(opts[:connection]) && fresh.respond_to?(:close)
            end
          end
        end

        public_class_method def self.reset(opts = {})
          consent(opts.merge(confirm: opts[:confirm]))
          session = begin_session(opts)
          raise CommandError, 'Full device reset is supported only over smartcard transport' unless session[:protocol] == :apdu

          before = read_information(session: session)
          bio_mpe = [6, 7].include?(before[:form_factor]) && before[:supported_capabilities].values.reduce(0, :|).anybits?(0x10)
          raise CommandError, 'Full device reset is not supported by this device; use application-specific resets' unless bio_mpe || before[:reset_blocked].positive?

          begin
            request(session: session, operation: :reset)
            after = read_information(session: session)
            verify_identity(before: before, after: after)
            raise ResponseError, 'Reset-state metadata is absent or not cleared' unless after[:raw_fields].key?(0x18) && after[:reset_blocked].zero? && after[:is_locked] == false

            { verified: true, verification: :reset_state_metadata, data_erasure_verified: false, info: after }
          rescue StandardError
            raise ResponseError, 'Device reset state uncertain: reset-state readback failed; do not automatically reset again', cause: nil
          end
        end

        public_class_method def self.reboot(opts = {})
          consent(opts.merge(confirm: opts[:confirm]))
          session = begin_session(opts)
          before = read_information(session: session)
          require_version(version: before[:version], minimum: [5, 0, 0])
          write_settings(opts.merge(session: session, before: before, changes: {}, reboot: true))
        end

        private_class_method def self.parse_mode(opts = {})
          value = opts[:value].to_s.upcase
          return MODES[value.to_i] if value.match?(/\A[0-6]\z/)

          names = { 'O' => 1, 'OTP' => 1, 'F' => 2, 'FIDO' => 2, 'C' => 4, 'CCID' => 4 }
          if value.start_with?('+', '-')
            raise ArgumentError, 'Current interfaces unavailable for relative mode changes' unless opts[:current]
            raise ArgumentError, 'Invalid relative USB mode syntax' unless value.match?(/\A(?:[+-](?:OTP|FIDO|CCID|O|F|C))+\z/)

            mask = opts[:current]
            value.scan(/([+-])([A-Z]+)/).each { |sign, name| mask = sign == '+' ? mask | names.fetch(name) : mask & ~names.fetch(name) }
          else
            raise ArgumentError, 'Invalid USB mode syntax' unless value.match?(/\A(?:OTP|FIDO|CCID|O|F|C)(?:\+(?:OTP|FIDO|CCID|O|F|C))*\z/)

            mask = value.split('+').reduce(0) { |bits, name| bits | names.fetch(name) }
          end
          raise ArgumentError, 'At least one USB interface must remain enabled' unless MODES.include?(mask)

          mask
        end

        private_class_method def self.observed_interfaces(opts = {})
          pid = opts[:descriptor][:product_id]
          return pid & 7 if pid.is_a?(Integer) && pid.between?(0x0401, 0x0407)

          { 0x0010 => 1, 0x0110 => 1, 0x0111 => 5, 0x0112 => 4, 0x0113 => 2, 0x0114 => 3, 0x0115 => 6, 0x0116 => 7, 0x0120 => 2, 0x0410 => 3 }[pid]
        end

        private_class_method def self.configure_applications(opts = {})
          transport = opts[:transport]
          modifiers = %i[enable disable enable_all disable_all touch_eject no_touch_eject autoeject_timeout chalresp_timeout restrict]
          changes_requested = modifiers.any? { |key| opts.key?(key) && opts[key] != false && opts[key] != [] && !opts[key].nil? }
          raise ArgumentError, 'List cannot be combined with configuration changes' if opts[:list] && changes_requested
          raise ArgumentError, 'No configuration options chosen' unless opts[:list] || changes_requested

          if opts[:list]
            result = info(opts)
            mask = result[:enabled_capabilities][transport]
            raise CommandError, 'Enabled capabilities unavailable for this transport' unless mask

            return { transport: transport, enabled: CAPABILITIES.filter_map { |name, bit| name if mask.anybits?(bit) }, mask: mask }
          end
          consent(opts.merge(confirm: opts[:confirm]))
          enable = capability_mask(value: opts.fetch(:enable, []))
          disable = capability_mask(value: opts.fetch(:disable, []))
          raise ArgumentError, 'Conflicting enable and disable options' if enable.anybits?(disable) || (opts[:enable_all] && opts[:disable_all])
          raise ArgumentError, 'Conflicting touch-eject options' if opts[:touch_eject] && opts[:no_touch_eject]

          changes = {}
          changes[6] = [numeric(value: opts[:autoeject_timeout], maximum: 65_535)].pack('n') if opts.key?(:autoeject_timeout)
          changes[7] = [numeric(value: opts[:chalresp_timeout], maximum: 255)].pack('C') if opts.key?(:chalresp_timeout)
          session = begin_session(opts)
          before = read_information(session: session)
          require_version(version: before[:version], minimum: [5, 0, 0])
          supported = before[:supported_capabilities][transport]
          enabled = before[:enabled_capabilities][transport]
          raise CommandError, 'This transport is not supported or lacks capability metadata' unless supported && enabled

          if opts[:restrict]
            raise ArgumentError, 'restrict is valid only for NFC and conflicts with capability changes' unless transport == :nfc && enable.zero? && disable.zero? && !opts[:enable_all] && !opts[:disable_all]

            require_version(version: before[:version], minimum: [5, 7, 0])
            reconnect = opts[:connection].descriptor[:transport] == :nfc
            return write_settings(opts.merge(session: session, before: before, changes: { 0x17 => "\1".b }, reconnect_required: reconnect, reboot: false))
          end
          raise CommandError, 'Applications can only be toggled on this device after reset' if before[:reset_blocked].positive?

          enable = supported if opts[:enable_all]
          disable = supported if opts[:disable_all]
          raise ArgumentError, 'Conflicting enable and disable options' if enable.anybits?(disable)
          raise CommandError, 'Requested application is not supported on this transport' if (enable | disable).anybits?(~supported)

          desired = (enabled | enable) & ~disable
          raise ArgumentError, 'Cannot disable all USB applications' if transport == :usb && desired.nobits?(CAPABILITIES.values.reduce(:|))

          changes[transport == :usb ? 3 : 0x0e] = [desired].pack('n')
          if opts[:touch_eject] || opts[:no_touch_eject]
            raise ResponseError, 'Missing device flag metadata' if before[:device_flags].nil?

            flags = opts[:touch_eject] ? before[:device_flags] | 0x80 : before[:device_flags] & ~0x80
            changes[8] = [flags].pack('C')
          end
          reboot = opts.fetch(:reboot, transport == :usb && interfaces(mask: enabled) != interfaces(mask: desired))
          write_settings(opts.merge(session: session, before: before, changes: changes, reboot: reboot))
        end

        private_class_method def self.write_settings(opts = {})
          before = opts[:before]
          changes = opts[:changes]
          reboot = opts.fetch(:reboot, false)
          raise ArgumentError, 'reboot must be true or false' unless [true, false].include?(reboot)

          reconnect = reboot || opts[:reconnect_required]
          raise ArgumentError, 'Disconnecting configuration changes require an explicit reconnect callable for readback' if reconnect && !opts[:reconnect].respond_to?(:call)

          raise ResponseError, 'Configuration lock metadata is unavailable; no write attempted' if before[:is_locked].nil?

          unlock = opts[:lock_code]
          if before[:is_locked]
            unlock = secret_value(opts.merge(value: unlock, name: :lock_code))
          elsif unlock
            raise ArgumentError, 'Device is not locked; do not supply lock_code'
          end
          raise ArgumentError, 'lock_code must contain exactly 16 raw bytes' if unlock && (!unlock.is_a?(String) || unlock.bytesize != 16)

          body = ''.b
          body << Protocol.tlv(tag: 0x0c, value: ''.b) if reboot
          body << Protocol.tlv(tag: 0x0b, value: unlock.b) if unlock
          changes.each { |tag, value| body << Protocol.tlv(tag: tag, value: value) }
          raise ArgumentError, 'Management configuration exceeds protocol bounds' if body.bytesize > 255 || (opts[:session][:protocol] == :otp && body.bytesize > 63)

          begin
            request(session: opts[:session], operation: :write, data: [body.bytesize].pack('C') + body)
            if reconnect
              fresh = opts[:reconnect].call(before.except(:raw_fields))
              raise ResponseError, 'Reconnect must return a fresh native connection' if fresh.equal?(opts[:session][:connection])

              after = info(connection: fresh, timeout: opts[:session][:timeout])
            else
              after = read_information(session: opts[:session])
            end
            verify_identity(before: before, after: after, reconnected: reconnect)
            changes.each do |tag, value|
              matches = if tag == 0x0a
                          after[:is_locked] == value.bytes.any?(&:positive?)
                        else
                          after[:raw_fields][tag] == value
                        end
              raise ResponseError, 'Device configuration readback mismatch' unless matches
            end
            { verified: true, verification: :device_information, info: after, reconnected: !!reconnect, lock_secret_readback: false }
          rescue StandardError
            raise ResponseError, 'Management write state uncertain: acknowledgment or readback failed; inspect the exact device, do not replay', cause: nil
          ensure
            fresh.close if fresh && !fresh.equal?(opts[:session][:connection]) && fresh.respond_to?(:close)
          end
        end

        private_class_method def self.verify_identity(opts = {})
          before = opts[:before]
          after = opts[:after]
          raise ResponseError, 'Readback device identity changed' unless before[:serial] == after[:serial] && before[:version] == after[:version]
          raise ResponseError, 'Serial-less readback requires the same observed explicit selector' if opts[:reconnected] && before[:serial].nil? && (before[:identity].nil? || before[:identity].empty? || before[:identity] != after[:identity])

          :matched
        end

        private_class_method def self.capability_mask(opts = {})
          values = opts[:value]
          values = [values] if values.is_a?(String) || values.is_a?(Symbol)
          raise ArgumentError, 'Capabilities must be names in an Array' unless values.is_a?(Array)

          values.reduce(0) do |mask, name|
            bit = CAPABILITIES[name.to_s.upcase]
            raise ArgumentError, 'Unknown application capability' unless bit

            mask | bit
          end
        end

        private_class_method def self.interfaces(opts = {})
          mask = opts[:mask]
          value = mask.anybits?(1) ? 1 : 0
          value |= 2 if mask.anybits?(0x202)
          value |= 4 if mask.anybits?(0x53c)
          value
        end

        private_class_method def self.numeric(opts = {})
          value = opts[:value]
          raise ArgumentError, 'Numeric option must be an unsigned decimal integer' unless value.is_a?(Integer) || (value.is_a?(String) && value.match?(/\A[0-9]+\z/))
          raise ArgumentError, 'Numeric option is outside the supported range' unless value.to_i.between?(0, opts[:maximum])

          value.to_i
        end

        private_class_method def self.secret_value(opts = {})
          value = opts[:value]
          value = opts[:secret_provider].call(opts[:name]) if value.nil? && opts[:secret_provider].respond_to?(:call)
          raise ArgumentError, "#{opts[:name]} must be supplied in memory" unless value.is_a?(String) && !value.empty?

          value.b
        end

        private_class_method def self.consent(opts = {})
          raise ConfirmationRequired, 'Device configuration requires confirm: true' unless opts[:confirm] == true

          %i[enable_all disable_all touch_eject no_touch_eject restrict clear generate reboot force list].each do |key|
            raise ArgumentError, "#{key} must be true or false" if opts.key?(key) && ![true, false].include?(opts[key])
          end

          :confirmed
        end

        private_class_method def self.begin_session(opts = {})
          connection = opts[:connection]
          timeout = opts.fetch(:timeout, 30)
          raise ArgumentError, 'connection must implement descriptor and exchange' unless connection.respond_to?(:descriptor) && connection.respond_to?(:exchange)
          raise ArgumentError, 'timeout must be finite positive seconds' unless (timeout.is_a?(Integer) || timeout.is_a?(Float)) && timeout.finite? && timeout.positive?

          session = { connection: connection, protocol: connection.descriptor[:protocol], timeout: timeout }
          case session[:protocol]
          when :otp
            raw = connection.exchange(protocol: :otp, command: 0, data: ''.b, response_length: 6, timeout: timeout)
            raise ResponseError, 'Malformed OTP status for management' unless raw.is_a?(String) && raw.bytesize == 6

            session[:version] = raw.bytes.take(3)
          when :apdu
            begin
              selected = Protocol.select(connection: connection, aid: AID, timeout: timeout)
            rescue Protocol::APDUError => e
              raise unless e.status == 0x6a82 && connection.descriptor[:transport] == :nfc

              raw = Protocol.select(connection: connection, aid: OTP_AID, timeout: timeout)
              raise ResponseError, 'NFC management fallback is only defined for legacy NEO' unless raw.bytesize == 6 && raw.getbyte(0) == 3

              return session.merge(version: raw.bytes.take(3), neo: true)
            end
            selected = selected.delete_suffix("\x90\0".b) # Edge duplicate status-word quirk.
            match = selected.match(/\A(?:YubiKey )?(\d+)\.(\d+)\.(\d+)\z/)
            raise ResponseError, 'Malformed management firmware version' unless match

            session[:version] = match.captures.map(&:to_i)
            if session[:version].first == 3
              # NEO arbitrator needs the documented deselect before selecting OTP.
              connection.exchange(protocol: :apdu, data: [0xa4, 4, 0, 8].pack('C*'), timeout: timeout)
              raw = Protocol.select(connection: connection, aid: OTP_AID, timeout: timeout)
              raise ResponseError, 'Malformed NEO OTP status' unless raw.bytesize == 6

              session[:neo] = true
            end
          when :ctap
            session[:version] = connection.descriptor[:version]
          else
            raise ArgumentError, 'Management requires OTP HID, smartcard or CTAP HID'
          end
          session
        end

        private_class_method def self.read_information(opts = {})
          session = opts[:session]
          version = session[:version]
          if version && (version <=> [1, 0, 0]) >= 0 && (version <=> [4, 1, 0]).negative?
            descriptor = session[:connection].descriptor
            return { version: version, serial: descriptor[:serial], identity: descriptor.slice(:device_path, :reader), usb_interfaces: observed_interfaces(descriptor: descriptor), supported_capabilities: {}, enabled_capabilities: {}, capabilities_source: :unavailable_on_legacy_firmware, raw_fields: {}, reset_blocked: 0 }
          end
          fields = {}
          finished = false
          256.times do |page|
            raw = request(session: session, operation: :read, page: page)
            raise ResponseError, 'Malformed management information length' unless raw.is_a?(String) && !raw.empty? && raw.getbyte(0) == raw.bytesize - 1

            more = false
            seen = {}
            Protocol.untlv(data: raw.byteslice(1..)).each do |record|
              tag = record[:tag]
              raise ResponseError, 'Duplicate management information field' if seen[tag]

              seen[tag] = true
              if tag == 0x10
                raise ResponseError, 'Invalid management pagination' unless ["\0".b, "\1".b].include?(record[:value])

                more = record[:value] == "\1".b
              else
                raise ResponseError, 'Duplicate management information field' if fields.key?(tag)

                fields[tag] = record[:value]
              end
            end
            unless more
              finished = true
              break
            end
          end
          raise ResponseError, 'Too many management information pages' unless finished

          descriptor = session[:connection].descriptor
          decode_information(fields: fields, version: version).merge(usb_interfaces: observed_interfaces(descriptor: descriptor), identity: descriptor.slice(:device_path, :reader))
        end

        private_class_method def self.decode_information(opts = {})
          fields = opts[:fields]
          version = fields[5]&.bytes || opts[:version]
          raise ResponseError, 'Missing or invalid management firmware version' unless version.is_a?(Array) && version.length == 3 && version.all? { |byte| byte.is_a?(Integer) && byte.between?(0, 255) }

          reported_version = version
          qualifier = { version: version, type: :final, iteration: 0 }
          if fields[0x19]
            qualified = Protocol.tlv_map(data: fields[0x19])
            qversion = version_field(value: qualified[1])
            qtype = integer_field(fields: qualified, tag: 2, sizes: [1])
            iteration = integer_field(fields: qualified, tag: 3, sizes: [1, 2, 3, 4])
            raise ResponseError, 'Invalid qualified firmware metadata' unless qversion && qtype.between?(0, 2)

            qualifier = { version: qversion, type: %i[alpha beta final][qtype], iteration: iteration }
            version = qversion unless qtype == 2
          end
          raise ResponseError, 'Missing USB supported capabilities' unless fields[1]

          supported = { usb: integer_field(fields: fields, tag: 1, sizes: [1, 2]) }
          enabled = {}
          supported[:usb] = 0x3f if version == [4, 2, 4] # Published firmware-reporting defect.
          enabled[:usb] = integer_field(fields: fields, tag: 3, sizes: [1, 2]) if fields[3] && version.first != 4
          if fields[0x0d]
            supported[:nfc] = integer_field(fields: fields, tag: 0x0d, sizes: [1, 2])
            enabled[:nfc] = integer_field(fields: fields, tag: 0x0e, sizes: [1, 2]) if fields[0x0e]
          end
          form = integer_field(fields: fields, tag: 4, sizes: [1], default: 0)
          serial = integer_field(fields: fields, tag: 2, sizes: [4], default: 0)
          {
            version: version, reported_version: reported_version, version_qualifier: qualifier, serial: serial.zero? ? nil : serial.to_s,
            form_factor: form & 15, is_fips: form.anybits?(0x80), is_sky: form.anybits?(0x40),
            supported_capabilities: supported, enabled_capabilities: enabled,
            is_locked: boolean_field(fields: fields, tag: 0x0a),
            auto_eject_timeout: integer_field(fields: fields, tag: 6, sizes: [2], default: nil),
            challenge_response_timeout: integer_field(fields: fields, tag: 7, sizes: [1], default: nil),
            device_flags: integer_field(fields: fields, tag: 8, sizes: [1], default: nil),
            nfc_restricted: boolean_field(fields: fields, tag: 0x17),
            reset_blocked: integer_field(fields: fields, tag: 0x18, sizes: [1, 2], default: 0),
            pin_complexity: boolean_field(fields: fields, tag: 0x16),
            fips_capable: fips_capabilities(value: integer_field(fields: fields, tag: 0x14, sizes: [1, 2], default: 0)),
            fips_approved: fips_capabilities(value: integer_field(fields: fields, tag: 0x15, sizes: [1, 2], default: 0)),
            part_number: text_field(value: fields[0x13]),
            fps_version: version_field(value: fields[0x20]), stm_version: version_field(value: fields[0x21]),
            raw_fields: fields, capabilities_source: :device_information
          }
        end

        private_class_method def self.text_field(opts = {})
          value = opts[:value]
          return nil if value.nil?

          text = value.dup.force_encoding(Encoding::UTF_8)
          raise ResponseError, 'Invalid management UTF8 metadata' unless text.valid_encoding?

          text
        end

        private_class_method def self.version_field(opts = {})
          value = opts[:value]
          return nil if value.nil?
          raise ResponseError, 'Invalid component firmware version' unless value.bytesize == 3

          value.bytes
        end

        private_class_method def self.integer_field(opts = {})
          raw = opts[:fields][opts[:tag]]
          return opts[:default] if raw.nil? && opts.key?(:default)
          raise ResponseError, 'Invalid management field length' unless raw && opts[:sizes].include?(raw.bytesize)

          raw.bytes.reduce(0) { |number, byte| (number << 8) | byte }
        end

        private_class_method def self.boolean_field(opts = {})
          raw = opts[:fields][opts[:tag]]
          return nil if raw.nil?
          raise ResponseError, 'Invalid management boolean field' unless ["\0".b, "\1".b].include?(raw)

          raw == "\1".b
        end

        private_class_method def self.fips_capabilities(opts = {})
          [0x200, 0x10, 0x08, 0x20, 0x100].each_with_index.sum { |mask, index| opts[:value].anybits?(1 << index) ? mask : 0 }
        end

        private_class_method def self.request(opts = {})
          session = opts[:session]
          operation = opts[:operation]
          data = opts.fetch(:data, ''.b)
          connection = session[:connection]
          case session[:protocol]
          when :otp
            command = { read: 0x13, write: 0x15, mode: 0x11 }.fetch(operation)
            data = [opts.fetch(:page, 0)].pack('C') if operation == :read
            connection.exchange(protocol: :otp, command: command, data: data, timeout: session[:timeout])
          when :apdu
            ins = { read: 0x1d, write: 0x1c, mode: 0x16, reset: 0x1f }.fetch(operation)
            ins = 1 if operation == :mode && session[:neo]
            p1 = if operation == :read
                   opts.fetch(:page, 0)
                 else
                   operation == :mode ? 0x11 : 0
                 end
            Protocol.apdu(connection: connection, ins: ins, p1: p1, data: data, timeout: session[:timeout])
          when :ctap
            command = { read: 0x42, write: 0x43, mode: 0x40 }.fetch(operation)
            data = [opts.fetch(:page, 0)].pack('C') if operation == :read
            connection.exchange(protocol: :ctap, command: command, data: data, timeout: session[:timeout])
          end
        end

        private_class_method def self.require_version(opts = {})
          raise CommandError, 'Operation is not supported by this device firmware' unless opts[:version].is_a?(Array) && (opts[:version] <=> opts[:minimum]) >= 0

          :supported
        end

        public_class_method def self.authors(opts = {})
          opts[:format]
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help(opts = {})
          opts[:format]
          puts <<~HELP
            Native Ruby only. No subprocess backend. Never log binary responses or secrets.
            Writes are sent once. Uncertain readback raises; inspect rather than replay.
            OTP keyboard/NDEF settings cannot export stored secrets; verification scope is explicit.
            # List prior device-configuration leaf operations without device traffic.
            #{self}.operations(
              format: 'optional - reserved output format'
            )
            # Dispatch a native device-configuration operation with nonsecret arguments.
            #{self}.execute(
              args: 'optional - Array after config, empty returns local metadata; force never grants consent',
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              lock_code: 'optional - current sixteen raw configuration-lock bytes; otherwise an explicit provider is consulted only if locked',
              reconnect: 'optional - callable returning a fresh native handle to the exact device after disconnect; required for reboot and legacy mode verification, returned handle is closed'
            )
            # Read exact firmware, supported applications and configuration metadata.
            #{self}.info(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds'
            )
            # Enable or disable USB applications with explicit field readback.
            #{self}.configure_usb(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              lock_code: 'optional - current sixteen raw configuration-lock bytes; otherwise an explicit provider is consulted only if locked',
              reconnect: 'optional - callable returning a fresh native handle to the exact device after disconnect; required for reboot and legacy mode verification, returned handle is closed',
              enable: 'optional - Array of exact application names to enable on this transport',
              disable: 'optional - Array of exact application names to disable on this transport',
              enable_all: 'optional - true enables only capabilities reported by this device',
              list: 'optional - true lists enabled applications without mutation and cannot mix with changes',
              reboot: 'optional - explicit boolean; USB interface changes default to reboot with reconnect verification',
              touch_eject: 'optional - true enables smartcard touch-eject',
              no_touch_eject: 'optional - true disables smartcard touch-eject',
              autoeject_timeout: 'optional - uint16 seconds before smartcard auto-eject',
              chalresp_timeout: 'optional - uint8 seconds allowed for an OTP touch'
            )
            # Enable or disable NFC applications and verify configuration fields.
            #{self}.configure_nfc(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              lock_code: 'optional - current sixteen raw configuration-lock bytes; otherwise an explicit provider is consulted only if locked',
              reconnect: 'optional - callable returning a fresh native handle to the exact device after disconnect; required for reboot and legacy mode verification, returned handle is closed',
              enable: 'optional - Array of exact application names to enable on this transport',
              disable: 'optional - Array of exact application names to disable on this transport',
              enable_all: 'optional - true enables only capabilities reported by this device',
              list: 'optional - true lists enabled applications without mutation and cannot mix with changes',
              reboot: 'optional - explicit boolean; USB interface changes default to reboot with reconnect verification',
              disable_all: 'optional - true disables all reported NFC applications, not USB',
              restrict: 'optional - true restricts NFC until USB power on firmware 5.7 or later'
            )
            # Set or clear configuration protection and read its lock flag.
            #{self}.set_lock_code(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              lock_code: 'optional - current sixteen raw configuration-lock bytes; otherwise an explicit provider is consulted only if locked',
              reconnect: 'optional - callable returning a fresh native handle to the exact device after disconnect; required for reboot and legacy mode verification, returned handle is closed',
              new_lock_code: 'optional - required sixteen raw replacement bytes unless clearing, generating or supplied by provider',
              clear: 'optional - true clears configuration protection',
              generate: 'optional - true generates sixteen bytes and requires secret_sink'
            )
            # Configure USB interfaces using modern capabilities or legacy mode bytes.
            #{self}.set_mode(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              lock_code: 'optional - current sixteen raw configuration-lock bytes; otherwise an explicit provider is consulted only if locked',
              reconnect: 'optional - callable returning a fresh native handle to the exact device after disconnect; required for reboot and legacy mode verification, returned handle is closed',
              mode: 'required - mode 0 through 6 or OTP+FIDO+CCID style string; relative forms require observed interfaces',
              touch_eject: 'optional - true requests CCID-only touch-eject',
              autoeject_timeout: 'optional - uint16 seconds; positive values imply touch-eject',
              chalresp_timeout: 'optional - uint8 touch timeout in seconds',
              reboot: 'optional - modern modes default to reboot if interfaces change; legacy needs physical reinsertion'
            )
            # Reset a reported supported Bio multi-protocol device and read reset metadata.
            #{self}.reset(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              lock_code: 'optional - current sixteen raw configuration-lock bytes; otherwise an explicit provider is consulted only if locked',
              reconnect: 'optional - callable returning a fresh native handle to the exact device after disconnect; required for reboot and legacy mode verification, returned handle is closed'
            )
            # Reboot and verify exact-device information through a fresh connection.
            #{self}.reboot(
              connection: 'required - exact selected native transport handle; caller owns its lifetime',
              confirm: 'required - literal true for a mutation or cryptographic operation; force does not grant consent',
              timeout: 'optional - finite positive timeout per device exchange, defaults to 30 seconds',
              secret_provider: 'optional - callable receiving a missing secret field Symbol; returns raw secret bytes in memory',
              secret_sink: 'optional - required callable for generation, receives field Symbol and secret bytes; never log them',
              lock_code: 'optional - current sixteen raw configuration-lock bytes; otherwise an explicit provider is consulted only if locked',
              reconnect: 'optional - callable returning a fresh native handle to the exact device after disconnect; required for reboot and legacy mode verification, returned handle is closed'
            )
            # Return module author information.
            #{self}.authors(
              format: 'optional - reserved output format'
            )
          HELP
          nil
        end
      end
    end
  end
end
