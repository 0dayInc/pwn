# frozen_string_literal: true

require 'io/console'
require 'fcntl'
require 'timeout'

module PWN
  module Plugins
    # Native Ruby YubiKey applications over bounded HID and smartcard transports.
    module YubiKey
      class Error < StandardError
      end

      class DependencyError < Error
      end

      class CommandError < Error
      end

      class TimeoutError < Error
      end

      class OutputLimitError < Error
      end

      class ConfirmationRequired < Error
      end

      class ResponseError < Error
      end

      autoload :Protocol, 'pwn/plugins/yubikey/protocol'
      autoload :Transport, 'pwn/plugins/yubikey/transport'
      autoload :OTP, 'pwn/plugins/yubikey/otp'
      autoload :Management, 'pwn/plugins/yubikey/management'
      autoload :OATH, 'pwn/plugins/yubikey/oath'
      autoload :HSMAuth, 'pwn/plugins/yubikey/hsmauth'
      autoload :PIV, 'pwn/plugins/yubikey/piv'
      autoload :FIDO, 'pwn/plugins/yubikey/fido'
      autoload :OpenPGP, 'pwn/plugins/yubikey/openpgp'
      autoload :SecurityDomain, 'pwn/plugins/yubikey/security_domain'

      # ykman 5.9.1 grammar: maximum nonsecret positionals, switches, value options.
      # Long options only: short aliases collide across application families.
      # Credential values are deliberately absent; use the operator terminal workflow.
      COMMANDS = {
        'list' => [0, %w[--serials --readers], %w[]],
        'info' => [0, %w[--check-fips], %w[]],
        'otp' => [0, %w[], %w[]],
        'otp info' => [0, %w[], %w[]],
        'otp swap' => [0, %w[--force], %w[]],
        'otp ndef' => [1, %w[], %w[--prefix --ndef-type]],
        'otp delete' => [1, %w[--force], %w[]],
        'otp yubiotp' => [1, %w[--enter --no-enter --serial-public-id --generate-private-id --generate-key --upload --force], %w[--public-id --config-output]],
        'otp static' => [1, %w[--generate --enter --no-enter --force], %w[--length --keyboard-layout]],
        'otp chalresp' => [1, %w[--touch --totp --generate --force], %w[]],
        'otp calculate' => [2, %w[--totp], %w[--digits]],
        'otp hotp' => [1, %w[--enter --no-enter --force], %w[--digits --counter --identifier]],
        'otp settings' => [1, %w[--force --delete-access-code --enter --no-enter --use-numeric-keypad --serial-usb-visible], %w[--pacing]],
        'openpgp' => [0, %w[], %w[]],
        'openpgp info' => [0, %w[], %w[]],
        'openpgp reset' => [0, %w[--force], %w[]],
        'openpgp access' => [0, %w[], %w[]],
        'openpgp access set-retries' => [3, %w[--force], %w[]],
        'openpgp access change-pin' => [0, %w[], %w[]],
        'openpgp access change-reset-code' => [0, %w[], %w[]],
        'openpgp access change-admin-pin' => [0, %w[], %w[]],
        'openpgp access unblock-pin' => [0, %w[], %w[]],
        'openpgp access set-signature-policy' => [1, %w[], %w[]],
        'openpgp keys' => [0, %w[], %w[]],
        'openpgp keys info' => [1, %w[], %w[]],
        'openpgp keys set-touch' => [2, %w[--force], %w[]],
        'openpgp keys import' => [2, %w[], %w[]],
        'openpgp keys attest' => [2, %w[], %w[--format]],
        'openpgp certificates' => [0, %w[], %w[]],
        'openpgp certificates export' => [2, %w[], %w[--format]],
        'openpgp certificates delete' => [1, %w[], %w[]],
        'openpgp certificates import' => [2, %w[], %w[]],
        'oath' => [0, %w[], %w[]],
        'oath info' => [0, %w[], %w[]],
        'oath reset' => [0, %w[--force], %w[]],
        'oath access' => [0, %w[], %w[]],
        'oath access change' => [0, %w[--clear --remember], %w[]],
        'oath access remember' => [0, %w[], %w[]],
        'oath access forget' => [0, %w[--all], %w[]],
        'oath accounts' => [0, %w[], %w[]],
        'oath accounts add' => [1, %w[--generate --touch --force --remember], %w[--oath-type --digits --algorithm --counter --issuer --period --output]],
        'oath accounts uri' => [0, %w[--touch --force --remember], %w[]],
        'oath accounts import' => [1, %w[--touch --force --remember], %w[]],
        'oath accounts list' => [0, %w[--show-hidden --oath-type --period --remember], %w[]],
        'oath accounts code' => [1, %w[--show-hidden --single --remember], %w[]],
        'oath accounts rename' => [2, %w[--force --remember], %w[]],
        'oath accounts delete' => [1, %w[--force --remember], %w[]],
        'piv' => [0, %w[], %w[]],
        'piv info' => [0, %w[], %w[]],
        'piv reset' => [0, %w[--force], %w[]],
        'piv access' => [0, %w[], %w[]],
        'piv access set-retries' => [2, %w[--force], %w[]],
        'piv access change-pin' => [0, %w[], %w[]],
        'piv access change-puk' => [0, %w[], %w[]],
        'piv access change-management-key' => [0, %w[--touch --protect --generate --force], %w[--algorithm]],
        'piv access unblock-pin' => [0, %w[], %w[]],
        'piv keys' => [0, %w[], %w[]],
        'piv keys generate' => [2, %w[], %w[--algorithm --format --pin-policy --touch-policy]],
        'piv keys import' => [2, %w[], %w[--pin-policy --touch-policy]],
        'piv keys attest' => [2, %w[], %w[--format]],
        'piv keys info' => [1, %w[], %w[]],
        'piv keys export' => [2, %w[--verify], %w[--format]],
        'piv keys move' => [2, %w[], %w[]],
        'piv keys delete' => [1, %w[], %w[]],
        'piv certificates' => [0, %w[], %w[]],
        'piv certificates import' => [2, %w[--verify --compress --update-chuid --no-update-chuid], %w[]],
        'piv certificates export' => [2, %w[], %w[--format]],
        'piv certificates generate' => [2, %w[--update-chuid --no-update-chuid], %w[--subject --valid-days --hash-algorithm]],
        'piv certificates request' => [3, %w[], %w[--subject --hash-algorithm]],
        'piv certificates delete' => [1, %w[--update-chuid --no-update-chuid], %w[]],
        'piv objects' => [0, %w[], %w[]],
        'piv objects export' => [2, %w[], %w[]],
        'piv objects import' => [2, %w[], %w[]],
        'piv objects generate' => [1, %w[], %w[]],
        'fido' => [0, %w[], %w[]],
        'fido info' => [0, %w[], %w[]],
        'fido reset' => [0, %w[--force], %w[]],
        'fido access' => [0, %w[], %w[]],
        'fido access change-pin' => [0, %w[--u2f], %w[]],
        'fido access verify-pin' => [0, %w[], %w[]],
        'fido access force-change' => [0, %w[], %w[]],
        'fido access set-min-length' => [1, %w[], %w[--rp-id]],
        'fido credentials' => [0, %w[], %w[]],
        'fido credentials list' => [0, %w[--csv], %w[]],
        'fido credentials delete' => [1, %w[--force], %w[]],
        'fido fingerprints' => [0, %w[], %w[]],
        'fido fingerprints list' => [0, %w[], %w[]],
        'fido fingerprints add' => [1, %w[], %w[]],
        'fido fingerprints rename' => [2, %w[], %w[]],
        'fido fingerprints delete' => [1, %w[--force], %w[]],
        'fido config' => [0, %w[], %w[]],
        'fido config toggle-always-uv' => [0, %w[], %w[]],
        'fido config enable-ep-attestation' => [0, %w[], %w[]],
        'config' => [0, %w[], %w[]],
        'config reset' => [0, %w[--force], %w[]],
        'config set-lock-code' => [0, %w[--force --clear --generate], %w[]],
        'config usb' => [0, %w[--force --list --enable-all --touch-eject --no-touch-eject], %w[--enable --disable --autoeject-timeout --chalresp-timeout]],
        'config nfc' => [0, %w[--force --enable-all --disable-all --list --restrict], %w[--enable --disable]],
        'config mode' => [1, %w[--touch-eject --force], %w[--autoeject-timeout --chalresp-timeout]],
        'apdu' => [256, %w[--no-pretty --short], %w[--app --send-apdu]],
        'hsmauth' => [0, %w[], %w[]],
        'hsmauth info' => [0, %w[], %w[]],
        'hsmauth reset' => [0, %w[--force], %w[]],
        'hsmauth credentials' => [0, %w[], %w[]],
        'hsmauth credentials list' => [0, %w[], %w[]],
        'hsmauth credentials generate' => [1, %w[--touch], %w[]],
        'hsmauth credentials import' => [2, %w[--touch], %w[]],
        'hsmauth credentials export' => [2, %w[], %w[--format]],
        'hsmauth credentials symmetric' => [1, %w[--generate --touch], %w[]],
        'hsmauth credentials derive' => [1, %w[--touch], %w[]],
        'hsmauth credentials delete' => [1, %w[--force], %w[]],
        'hsmauth credentials change-password' => [1, %w[], %w[]],
        'hsmauth access' => [0, %w[], %w[]],
        'hsmauth access change-management-key' => [0, %w[--generate], %w[]],
        'hsmauth access change-management-password' => [0, %w[], %w[]],
        'sd' => [0, %w[], %w[]],
        'sd info' => [0, %w[], %w[]],
        'sd reset' => [0, %w[--force], %w[]],
        'sd keys' => [0, %w[], %w[]],
        'sd keys generate' => [3, %w[], %w[--replace-kvn]],
        'sd keys import' => [3, %w[], %w[--replace-kvn]],
        'sd keys export' => [3, %w[], %w[]],
        'sd keys delete' => [2, %w[--force], %w[]],
        'sd keys set-allowlist' => [256, %w[], %w[]]
      }.transform_values { |entry| entry.each(&:freeze).freeze }.freeze

      SELECTOR_OPTIONS = %i[serial reader device_path timeout].freeze
      COMMON_OPTIONS = (SELECTOR_OPTIONS + %i[connection confirm secure_channel secret_provider]).freeze
      NATIVE_OPTIONS = {
        'otp' => %i[key password access_code new_access_code private_id public_id generate generate_key generate_private_id secret_sink touch totp digits counter identifier key_encoding keyboard_layout length prefix ndef_type config_output enter no_enter serial_public_id delete_access_code use_numeric_keypad serial_usb_visible pacing verification_challenge challenge timestamp],
        'config' => %i[lock_code new_lock_code secret_sink reconnect enable disable enable_all disable_all touch_eject no_touch_eject autoeject_timeout chalresp_timeout restrict clear generate reboot list mode],
        'oath' => %i[password new_password access_key new_access_key timestamp encrypted_cache remember use_cache secret secret_base32 uri credentials pskc pskc_password pskc_key oath_type algorithm digits period counter issuer touch generate overwrite],
        'hsmauth' => %i[management_key new_management_key new_management_password credential_password new_credential_password password derivation_password key_enc key_mac private_key key_password public_key touch generate],
        'piv' => %i[pin new_pin puk new_puk management_key new_management_key management_algorithm algorithm input password certificate_serial extensions fips_restrictions secret_sink generate protect touch pin_policy touch_policy use_protected_key temporary_pin request_temporary_pin block_retries subject valid_days hash_algorithm not_before not_after compress update_chuid no_update_chuid verify format public_key_source],
        'fido' => %i[pin new_pin u2f uv rp_ids min_length on_keepalive cancelled on_sample max_records max_samples capture_timeout_ms],
        'openpgp' => %i[pin new_pin admin_pin new_admin_pin reset_code new_reset_code use_admin key key_password certificate],
        'sd' => %i[key key_enc key_mac key_dek certificate certificates ski curve replace_kvn serials]
      }.transform_values(&:freeze).freeze
      FAMILIES = {
        'otp' => %i[OTP otp], 'config' => %i[Management management],
        'oath' => %i[OATH oath], 'hsmauth' => %i[HSMAuth hsmauth],
        'piv' => %i[PIV piv], 'fido' => %i[FIDO fido],
        'openpgp' => %i[OpenPGP openpgp], 'sd' => %i[SecurityDomain security_domain]
      }.freeze

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.available?(opts = {})
        validate_options(options: opts, allowed: %i[backend application])
        Transport.available?(opts.slice(:backend, :application))
      end

      public_class_method def self.devices(opts = {})
        validate_options(options: opts, allowed: SELECTOR_OPTIONS + [:backend])
        validate_selection(opts.merge(serial: opts[:serial]))
        Transport.devices(opts)
      end

      public_class_method def self.challenge_response(opts = {})
        validate_options(options: opts, allowed: COMMON_OPTIONS + %i[challenge slot])
        validate_selection(opts)
        validate_slot(slot: opts.fetch(:slot, 2))
        challenge = opts[:challenge]
        raise ArgumentError, 'challenge must contain 1 to 64 raw bytes, not pre-encoded hex' unless challenge.is_a?(String) && challenge.bytesize.between?(1, 64)

        # Omitted confirm is the vault unlock path. An explicit flag must still be literal true.
        Protocol.require_confirm(opts) if opts.key?(:confirm)
        result = with_connection(opts.merge(application: :otp)) { |connection| OTP.challenge_response(opts.merge(connection: connection)) }
        raise ResponseError, 'OTP must return exactly 20 raw HMAC bytes' unless result.is_a?(String) && result.bytesize == 20

        result.b
      end

      public_class_method def self.provision_challenge_response(opts = {})
        validate_options(options: opts, allowed: COMMON_OPTIONS + %i[key slot access_code new_access_code touch verification_challenge])
        validate_selection(opts)
        Protocol.require_confirm(opts)
        validate_slot(slot: opts.fetch(:slot, 2))
        key = opts[:key]
        raise ArgumentError, 'key must contain exactly 20 raw bytes' unless key.is_a?(String) && key.bytesize == 20
        raise ArgumentError, 'Provisioning requires an explicit serial, reader, device_path or connection' unless opts[:serial] || opts[:reader] || opts[:device_path] || opts[:connection]
        raise ArgumentError, 'touch must be a boolean' unless [true, false].include?(opts.fetch(:touch, true))

        %i[access_code new_access_code].each do |name|
          value = opts[name]
          raise ArgumentError, 'OTP access codes must contain six raw bytes' unless value.nil? || (value.is_a?(String) && value.bytesize == 6)
        end
        challenge = opts[:verification_challenge]
        raise ArgumentError, 'verification_challenge must contain 1 to 64 raw bytes' unless challenge.nil? || (challenge.is_a?(String) && challenge.bytesize.between?(1, 64))

        result = with_connection(opts.merge(application: :otp)) { |connection| OTP.provision_challenge_response(opts.merge(connection: connection)) }
        raise ResponseError, 'OTP provisioning verification failed; inspect the device before retrying' unless result == :verified || (result.is_a?(Hash) && result[:verified] == true && result[:verification] == :hmac_sha1)

        :verified
      end

      public_class_method def self.oath_code(opts = {})
        validate_options(options: opts, allowed: COMMON_OPTIONS + %i[account timestamp password access_key encrypted_cache remember use_cache])
        validate_selection(opts)
        account = opts[:account]
        raise ArgumentError, 'account must contain 1 to 64 exact control-free bytes' unless account.is_a?(String) && account.bytesize.between?(1, 64) && account.valid_encoding? && !account.b.match?(/[\x00-\x1f\x7f]/)

        timestamp = opts[:timestamp]
        raise ArgumentError, 'timestamp must be a nonnegative Integer' unless timestamp.nil? || (timestamp.is_a?(Integer) && timestamp.between?(0, 0x7fffffffffffffff))

        validate_oath_options(opts)
        Protocol.require_confirm(opts)
        result = with_connection(opts.merge(application: :oath)) { |connection| OATH.code(opts.merge(connection: connection)) }
        raise ResponseError, 'OATH must return exactly one numeric code' unless result.is_a?(String) && result.match?(/\A[0-9]{6,8}\z/)

        result
      end

      public_class_method def self.info(opts = {})
        validate_options(options: opts, allowed: COMMON_OPTIONS)
        validate_selection(opts.merge(connection: opts[:connection]))
        with_connection(opts.merge(application: :management)) { |connection| Management.info(opts.merge(connection: connection)) }
      end

      public_class_method def self.cli_help(opts = {})
        validate_options(options: opts, allowed: SELECTOR_OPTIONS + [:path])
        validate_selection(opts)
        path = opts[:path] || []
        raise ArgumentError, 'path must contain only supported native command names' unless path.is_a?(Array) && path.all? { |part| part.is_a?(String) && part.match?(/\A[a-z][a-z0-9-]*\z/) }
        return { backend: :native, families: FAMILIES.keys, operations: %w[list info apdu] } if path.empty?
        return { backend: :native, operations: [path.first] } if path.length == 1 && %w[list info apdu].include?(path.first)

        route = FAMILIES[path.first]
        raise ArgumentError, 'Unknown native help path' unless route

        prefix = path.drop(1).join(' ')
        operations = const_get(route[0], false).operations.select { |entry| prefix.empty? || entry == prefix || entry.start_with?("#{prefix} ") }
        raise ArgumentError, 'Unknown native help path' if operations.empty?

        { backend: :native, application: route[1], path: path.dup, operations: operations }
      end

      public_class_method def self.config(opts = {})
        family(opts.merge(family: 'config', args: opts[:args]))
      end

      public_class_method def self.otp(opts = {})
        family(opts.merge(family: 'otp', args: opts[:args]))
      end

      public_class_method def self.oath(opts = {})
        family(opts.merge(family: 'oath', args: opts[:args]))
      end

      public_class_method def self.fido(opts = {})
        family(opts.merge(family: 'fido', args: opts[:args]))
      end

      public_class_method def self.piv(opts = {})
        family(opts.merge(family: 'piv', args: opts[:args]))
      end

      public_class_method def self.openpgp(opts = {})
        family(opts.merge(family: 'openpgp', args: opts[:args]))
      end

      public_class_method def self.hsmauth(opts = {})
        family(opts.merge(family: 'hsmauth', args: opts[:args]))
      end

      public_class_method def self.security_domain(opts = {})
        family(opts.merge(family: 'sd', args: opts[:args]))
      end

      public_class_method def self.apdu(opts = {})
        validate_options(options: opts, allowed: COMMON_OPTIONS + %i[args application ins cla p1 p2 data le extended max_response])
        validate_selection(opts)
        args = opts[:args]
        return cli_help(path: ['apdu']) if !opts.key?(:ins) && (args.nil? || args == [] || args == ['--help'])

        Protocol.require_confirm(opts)
        if opts.key?(:ins)
          raise ArgumentError, 'Do not combine typed APDU fields and argv' unless args.nil?

          validate_apdu_fields(opts)
          application = opts.fetch(:application, :security_domain)
          raise ArgumentError, 'Unknown APDU application selector' unless FAMILIES.values.map(&:last).include?(application)

          return with_connection(opts.merge(application: application)) do |connection|
            Protocol.apdu(opts.slice(:ins, :cla, :p1, :p2, :data, :le, :extended, :max_response, :timeout).merge(connection: connection))
          end
        end
        raise ArgumentError, 'Typed APDU fields require ins' if opts.keys.intersect?(%i[data cla p1 p2 le extended max_response application])

        prepared = prepare_apdus(args: validate_args(args: args))
        with_connection(opts.merge(application: prepared[:application])) do |connection|
          raise ArgumentError, 'Raw APDUs require smartcard transport' unless connection.descriptor[:protocol] == :apdu

          Protocol.select(connection: connection, aid: prepared[:aid], timeout: opts.fetch(:timeout, 30)) if prepared[:aid]
          prepared[:frames].map do |frame|
            response = connection.exchange(protocol: :apdu, data: frame[:data], timeout: opts.fetch(:timeout, 30))
            raise ResponseError, 'Malformed raw APDU response' unless response.is_a?(String) && response.bytesize.between?(2, Protocol::MAX_BYTES)

            status = response.byteslice(-2, 2).unpack1('n')
            raise Protocol::APDUError.new(status: status) if frame[:expected] && status != frame[:expected]

            { data: response.byteslice(0, response.bytesize - 2).b, status: status }
          end
        end
      end

      public_class_method def self.command(opts = {})
        args = validate_args(args: opts[:args])
        return cli_help(opts.except(:args).merge(path: [])) if [%w[--help], %w[--full-help]].include?(args)
        return cli_help(opts.except(:args, :confirm).merge(path: args[0...-1])) if args.last == '--help'
        return info(opts.except(:args)) if args == ['info']
        return apdu(opts.merge(args: args.drop(1))) if args.first == 'apdu'
        return devices(opts.except(:args)) if args == ['list']

        if [%w[list --serials], %w[list --readers]].include?(args)
          key = args.last == '--serials' ? :serial : :reader
          return devices(opts.except(:args)).filter_map { |entry| entry[key] }.uniq
        end
        validate_options(options: opts, allowed: COMMON_OPTIONS + [:args] + NATIVE_OPTIONS.fetch(args.first, []))
        validate_selection(opts)
        family = args.first
        route = FAMILIES[family]
        raise ArgumentError, 'Unknown native YubiKey command' unless route

        child = const_get(route[0], false)
        path = child.operations.sort_by { |entry| -entry.split.length }.find { |entry| args.drop(1).take(entry.split.length) == entry.split }
        return cli_help(opts.slice(*SELECTOR_OPTIONS).merge(path: args)) unless path

        validate_command(args: args, path: "#{family} #{path}")
        Protocol.require_confirm(opts) unless read_only?(opts.merge(path: "#{family} #{path}", args: args))
        with_connection(opts.merge(application: route[1])) do |connection|
          child.execute(opts.merge(args: args.drop(1), connection: connection))
        end
      end

      public_class_method def self.interact(opts = {})
        Protocol.require_confirm(opts)
        raise ArgumentError, 'Private terminal use requires operator: true outside agent requests' unless opts[:operator] == true && Thread.current[:pwn_request_runtime].nil?
        raise ArgumentError, 'interact owns its private credential provider' if opts.key?(:secret_provider)

        args = validate_args(args: opts[:args])
        validate_options(options: opts, allowed: COMMON_OPTIONS + %i[args terminal operator] + NATIVE_OPTIONS.fetch(args.first, []))
        validate_selection(opts)
        terminal = opts[:terminal].nil? ? IO.console : opts[:terminal]
        validate_terminal(terminal: terminal)
        flags = terminal.fcntl(Fcntl::F_GETFL)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + opts.fetch(:timeout, 30)
        secrets = []
        active = true
        provider = lambda do |name|
          raise ArgumentError, 'Private input callback is no longer active' unless active
          raise ArgumentError, 'Invalid private credential field name' unless name.is_a?(Symbol) && name.to_s.match?(/\A[a-z_]{1,64}\z/)

          remaining = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          raise TimeoutError, 'Private YubiKey input timed out' unless remaining.positive?

          value = ::Timeout.timeout(remaining, TimeoutError, 'Private YubiKey input timed out') do
            terminal.noecho { terminal.getpass("YubiKey #{name.to_s.tr('_', ' ')}: ") }
          end
          raise CommandError, 'Private YubiKey input ended without a credential' unless value.is_a?(String) && !value.empty?

          secrets << value
          value
        end
        command(opts.except(:terminal, :operator).merge(args: args, secret_provider: provider,
                                                        timeout: deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)))
        raise TimeoutError, 'Private YubiKey operation timed out' unless Process.clock_gettime(Process::CLOCK_MONOTONIC) < deadline

        :completed
      rescue IOError, SystemCallError
        raise CommandError, 'Private YubiKey terminal failed; device state may need inspection', cause: nil
      ensure
        active = false
        secrets&.each { |value| value.replace("\0".b * value.bytesize) unless value.frozen? }
        secrets&.clear
        terminal.fcntl(Fcntl::F_SETFL, flags) if flags && terminal && !terminal.closed?
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts <<~HELP
          USAGE:
          Native Ruby YubiKey applications over HID and smartcard transports.
          No ykman process is started. Secrets stay in memory. One total deadline
          covers open, authentication and commands. Existing-slot HMAC does not
          require confirm; mutations, OATH and provisioning do.

          # Return the empty executable dependency list.
          #{self}.required_bins

          # Probe host libraries without discovering or opening a device.
          #{self}.available?(
            backend: 'optional - hid or pcsc',
            application: 'optional - otp, oath, piv, openpgp, fido, management, hsmauth or security_domain'
          )

          # Explicitly list native descriptors.
          #{self}.devices(
            serial: 'optional - exact decimal serial String',
            reader: 'optional - nonempty smartcard reader String',
            device_path: 'optional - nonempty device path String',
            timeout: 'optional - finite positive seconds, defaults to 30',
            backend: 'optional - hid or pcsc'
          )

          # Return 20 raw HMAC-SHA1 bytes from an already provisioned slot.
          #{self}.challenge_response(
            challenge: 'required - raw String of 1 to 64 bytes',
            slot: 'optional - integer 1 or 2, defaults to 2',
            serial: 'optional - exact decimal serial String',
            reader: 'optional - nonempty smartcard reader String',
            device_path: 'optional - nonempty device path String',
            timeout: 'optional - finite positive seconds, defaults to 30',
            connection: 'optional - caller-owned native exchange connection'
          )

          # Overwrite an OTP slot and verify a fresh HMAC before returning.
          #{self}.provision_challenge_response(
            key: 'required - exactly 20 raw key bytes',
            confirm: 'required - literal true',
            slot: 'optional - integer 1 or 2, defaults to 2',
            serial: 'optional - exact decimal serial String; one selector is required',
            reader: 'optional - nonempty smartcard reader String',
            device_path: 'optional - nonempty device path String',
            connection: 'optional - caller-owned native exchange connection',
            timeout: 'optional - finite positive seconds, defaults to 30',
            touch: 'optional - boolean, defaults to true',
            access_code: 'optional - six raw access-code bytes',
            new_access_code: 'optional - six raw replacement access-code bytes',
            verification_challenge: 'optional - raw challenge of 1 to 64 bytes'
          )

          # Return one exact-account OATH code, preserving leading zeros.
          #{self}.oath_code(
            account: 'required - exact account String of 1 to 64 bytes',
            confirm: 'required - literal true',
            timestamp: 'optional - nonnegative Integer epoch seconds',
            password: 'optional - nonempty in-memory OATH password',
            access_key: 'optional - 16 raw access-key bytes',
            serial: 'optional - exact decimal serial String',
            reader: 'optional - nonempty smartcard reader String',
            device_path: 'optional - nonempty device path String',
            timeout: 'optional - finite positive seconds, defaults to 30',
            connection: 'optional - caller-owned native exchange connection',
            remember: 'optional - boolean cache control; requires encrypted_cache',
            use_cache: 'optional - boolean cache control; requires encrypted_cache',
            encrypted_cache: 'optional - caller adapter with encrypted?, fetch, store and delete'
          )

          # Read structured management information.
          #{self}.info(
            serial: 'optional - exact decimal serial String',
            reader: 'optional - nonempty smartcard reader String',
            device_path: 'optional - nonempty device path String',
            timeout: 'optional - finite positive seconds, defaults to 30',
            connection: 'optional - caller-owned native exchange connection'
          )

          # Return local native help metadata without opening a device.
          #{self}.cli_help(
            path: 'optional - Array of supported command name Strings'
          )

          # Dispatch a config leaf through the native management application.
          #{self}.config(args: 'optional - argv after the family name')

          # Dispatch an otp leaf through the native OTP application.
          #{self}.otp(args: 'optional - argv after the family name')

          # Dispatch an oath leaf through the native OATH application.
          #{self}.oath(args: 'optional - argv after the family name')

          # Dispatch a fido leaf through the native FIDO application.
          #{self}.fido(args: 'optional - argv after the family name')

          # Dispatch a piv leaf through the native PIV application.
          #{self}.piv(args: 'optional - argv after the family name')

          # Dispatch an openpgp leaf through the native OpenPGP application.
          #{self}.openpgp(args: 'optional - argv after the family name')

          # Dispatch an hsmauth leaf through the native HSM Auth application.
          #{self}.hsmauth(args: 'optional - argv after the family name')

          # Dispatch a security_domain leaf through the native Security Domain application.
          #{self}.security_domain(args: 'optional - argv after the family name')

          # Send an explicit smartcard command. Mutations require confirm: true.
          #{self}.apdu(
            args: 'optional - compact or full APDU argv; omit with ins for typed fields',
            ins: 'optional - integer instruction byte for a typed APDU',
            cla: 'optional - integer class byte, defaults to zero',
            p1: 'optional - integer parameter byte, defaults to zero',
            p2: 'optional - integer parameter byte, defaults to zero',
            data: 'optional - raw command bytes',
            le: 'optional - expected response length',
            extended: 'optional - boolean extended framing',
            application: 'optional - native application Symbol for a typed APDU',
            max_response: 'optional - positive response byte limit',
            confirm: 'required - literal true before a device APDU',
            timeout: 'optional - finite positive seconds, defaults to 30',
            connection: 'optional - caller-owned native exchange connection'
          )

          # Dispatch a supported leaf to its native Ruby application.
          #{self}.command(
            args: 'required - nonsecret command Array including the family name',
            confirm: 'required - literal true for mutations and OATH calculation',
            serial: 'optional - exact decimal serial String',
            reader: 'optional - nonempty smartcard reader String',
            device_path: 'optional - nonempty device path String',
            timeout: 'optional - finite positive seconds, defaults to 30',
            connection: 'optional - caller-owned native exchange connection',
            secret_provider: 'optional - callable receiving a field Symbol',
            secure_channel: 'optional - explicit SCP selector Hash'
          )

          # Prompt on a private operator terminal and run one native command.
          #{self}.interact(
            args: 'required - nonsecret command Array',
            confirm: 'required - literal true',
            operator: 'required - literal true outside an agent request',
            terminal: 'optional - readable and writable IO terminal',
            timeout: 'optional - finite positive seconds including human input, defaults to 30',
            serial: 'optional - exact decimal serial String',
            reader: 'optional - nonempty smartcard reader String',
            device_path: 'optional - nonempty device path String',
            connection: 'optional - caller-owned native exchange connection'
          )

          # Return module author information without device access.
          #{self}.authors
        HELP
        nil
      end

      private_class_method def self.validate_terminal(opts = {})
        terminal = opts[:terminal]
        raise ArgumentError, 'A private readable and writable IO terminal is required' unless terminal.is_a?(IO) && !terminal.closed? && terminal.tty?

        # Ruby's wrapper modes can be narrower than the descriptor's O_RDWR.
        # These probes consume no bytes and do not alter descriptor ownership.
        terminal.read(0)
        terminal.syswrite('')
      rescue IOError, SystemCallError
        raise ArgumentError, 'A private readable and writable IO terminal is required', cause: nil
      end

      private_class_method def self.validate_apdu_fields(opts = {})
        %i[ins cla p1 p2].each do |key|
          value = opts.fetch(key, 0)
          raise ArgumentError, 'APDU header fields must be integer bytes' unless value.is_a?(Integer) && value.between?(0, 255)
        end
        data = opts.fetch(:data, ''.b)
        raise ArgumentError, 'APDU data must be a bounded raw String' unless data.is_a?(String) && data.bytesize <= Protocol::MAX_BYTES
        raise ArgumentError, 'extended must be a boolean' unless [true, false].include?(opts.fetch(:extended, false))

        le = opts[:le]
        raise ArgumentError, 'APDU Le must fit its frame encoding' unless le.nil? || (le.is_a?(Integer) && le.between?(0, opts[:extended] ? 65_536 : 256))

        limit = opts.fetch(:max_response, Protocol::MAX_BYTES)
        raise ArgumentError, 'max_response must be a bounded positive Integer' unless limit.is_a?(Integer) && limit.between?(1, Protocol::MAX_BYTES)
      end

      private_class_method def self.prepare_apdus(opts = {})
        parsed = Protocol.parse_args(args: opts[:args], flags: %w[--no-pretty --short], values: %w[--app --send-apdu])
        values = parsed[:options]
        application = :security_domain
        if values[:app]
          route = FAMILIES[values[:app]]
          raise ArgumentError, 'Unknown APDU application name' unless route

          application = route[1]
          child = const_get(route[0], false)
          raise ArgumentError, 'Application has no smartcard AID' unless child.const_defined?(:AID, false)

          aid = child.const_get(:AID, false)
        end
        if values[:send_apdu]
          raise ArgumentError, 'Full APDUs cannot be combined with application or compact commands' if aid || !parsed[:positionals].empty?

          frames = Array(values[:send_apdu]).map do |value|
            raise ArgumentError, 'A full APDU must be even hex containing 4 to 65544 bytes' unless value.match?(/\A(?:[0-9a-fA-F]{2}){4,65544}\z/)

            { data: [value].pack('H*'), expected: nil }
          end
        else
          frames = parsed[:positionals].map { |value| compact_apdu(value: value, short: values[:short]) }
        end
        raise ArgumentError, 'At least one APDU or explicit application is required' if frames.empty? && aid.nil?

        { application: application, aid: aid, frames: frames }
      end

      private_class_method def self.compact_apdu(opts = {})
        # Compatibility syntax is a local parser, never executable input.
        match = opts[:value].match(%r{\A(?<cla>[0-9a-f]{2})?(?<ins>[0-9a-f]{2})(?<params>[0-9a-f]{4})?(?::(?<body>(?:[0-9a-f]{2})+))?(?:/(?<le>[0-9a-f]{2}))?(?<check>=(?<sw>[0-9a-f]{4})?)?\z}i)
        raise ArgumentError, 'Malformed compact APDU syntax' unless match

        header = [match[:cla] ? match[:cla].to_i(16) : 0, match[:ins].to_i(16), *(match[:params] || '0000').scan(/../).map { |value| value.to_i(16) }].pack('C*')
        data = [match[:body] || ''].pack('H*')
        le = match[:le] ? match[:le].to_i(16) : 0
        if data.bytesize > 255
          raise ArgumentError, 'Compact APDU data exceeds selected encoding' if opts[:short] || data.bytesize > 65_535

          encoded = header + "\0".b + [data.bytesize].pack('n') + data + [le].pack('n')
        else
          encoded = header + (data.empty? ? ''.b : [data.bytesize].pack('C') + data) + [le].pack('C')
        end
        expected = if match[:check]
                     match[:sw].to_s.empty? ? 0x9000 : match[:sw].to_i(16)
                   end
        { data: encoded, expected: expected }
      end

      private_class_method def self.validate_slot(opts = {})
        slot = opts[:slot]
        raise ArgumentError, 'slot must be integer 1 or 2' unless slot.is_a?(Integer) && [1, 2].include?(slot)
      end

      private_class_method def self.validate_oath_options(opts = {})
        password = opts[:password]
        key = opts[:access_key]
        raise ArgumentError, 'password must be a nonempty in-memory String' unless password.nil? || (password.is_a?(String) && !password.empty?)
        raise ArgumentError, 'access_key must contain 16 raw bytes' unless key.nil? || (key.is_a?(String) && key.bytesize == 16)
        raise ArgumentError, 'Choose password or access_key, not both' if password && key
        raise ArgumentError, 'use_cache conflicts with an explicit credential' if opts[:use_cache] && (password || key)

        %i[remember use_cache].each do |name|
          raise ArgumentError, 'OATH cache controls must be booleans' if opts.key?(name) && ![true, false].include?(opts[name])
        end
        return unless opts[:remember] || opts[:use_cache]

        cache = opts[:encrypted_cache]
        raise ArgumentError, 'Supply an explicit encrypted_cache adapter; no host cache is opened' unless cache.respond_to?(:encrypted?) && cache.encrypted? == true && %i[fetch store delete].all? { |name| cache.respond_to?(name) }
      end

      private_class_method def self.family(opts = {})
        args = opts[:args]
        raise ArgumentError, 'args must be an Array' unless args.nil? || args.is_a?(Array)

        command(opts.except(:family).merge(args: [opts[:family]] + (args || [])))
      end

      # One deadline spans acquisition, secure-channel setup and all application I/O.
      # Closing this lease never closes a caller-owned underlying descriptor.
      class DeadlineConnection
        def initialize(opts, deadline)
          @connection = opts[:connection]
          @owned = @connection.nil?
          @selection = opts.slice(*SELECTOR_OPTIONS).merge(application: opts[:application])
          @deadline = deadline
        end

        def acquire
          @connection ||= Transport.open(@selection.merge(timeout: remaining))
          remaining
          @connection
        end

        def release
          handle = @connection
          @connection = nil
          handle.close if @owned && handle
          :released
        end

        def remaining
          seconds = @deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC)
          raise TimeoutError, 'Native YubiKey operation timed out; inspect device state before retrying' unless seconds.positive?

          seconds
        end

        def exchange(opts = {})
          timeout = opts.fetch(:timeout, remaining)
          raise ArgumentError, 'exchange timeout must be finite positive seconds' unless timeout.is_a?(Numeric) && timeout.finite? && timeout.positive?

          handle = acquire
          result = handle.exchange(**opts, timeout: [timeout, remaining].min)
          remaining
          result
        end

        def descriptor
          remaining
          value = acquire.descriptor
          remaining
          value
        end

        def close
          :released
        end

        def inspect
          '#<YubiKey deadline connection>'
        end
      end
      private_constant :DeadlineConnection

      private_class_method def self.with_connection(opts = {})
        timeout = opts.fetch(:timeout, 30)
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
        lease = DeadlineConnection.new(opts, deadline)
        wrapped = nil
        lease.remaining
        if opts[:secure_channel]
          lease.acquire
          wrapped = SecurityDomain.secure_connection(opts[:secure_channel].merge(connection: lease, confirm: opts[:confirm], timeout: lease.remaining))
          raise ResponseError, 'Secure-channel handshake did not return a native connection' unless wrapped.respond_to?(:exchange)
        end
        result = yield(wrapped || lease)
        lease.remaining
        result
      rescue IOError, SystemCallError
        raise CommandError, 'Native YubiKey I/O failed; inspect device state before retrying', cause: nil
      ensure
        begin
          wrapped.close if wrapped
        ensure
          lease&.release
        end
      end

      private_class_method def self.read_only?(opts = {})
        path = opts[:path]
        args = opts[:args]
        return true if path.end_with?(' info') || path == 'hsmauth credentials list'

        if path == 'oath accounts list'
          return false if args.include?('--remember') || %i[password access_key secret_provider remember use_cache].any? { |name| opts[name] }

          return true # A protected application still checks consent before authenticating.
        end
        return false unless %w[config].include?(args.first) && %w[usb nfc].include?(args[1])
        return false unless args.drop(2) == ['--list'] || (args.length == 2 && opts[:list] == true)

        !opts.keys.intersect?(NATIVE_OPTIONS.fetch('config') - [:list])
      end

      private_class_method def self.validate_options(opts = {})
        raise ArgumentError, 'Unknown YubiKey option; use native operation options' unless opts[:options].is_a?(Hash) && (opts[:options].keys - opts[:allowed]).empty?
      end

      private_class_method def self.validate_selection(opts = {})
        serial = opts[:serial]
        raise ArgumentError, 'serial must be an exact decimal String' unless serial.nil? || (serial.is_a?(String) && serial.match?(/\A[0-9]+\z/))

        %i[reader device_path].each do |key|
          value = opts[key]
          raise ArgumentError, 'reader and device_path must be nonempty control-free Strings' unless value.nil? || (value.is_a?(String) && !value.empty? && value.valid_encoding? && !value.b.match?(/[\x00-\x1f\x7f]/))
        end
        timeout = opts.fetch(:timeout, 30)
        raise ArgumentError, 'timeout must be finite positive seconds' unless (timeout.is_a?(Integer) || timeout.is_a?(Float)) && timeout.finite? && timeout.positive?
        raise ArgumentError, 'connection must implement native exchange' if opts.key?(:connection) && !opts[:connection].nil? && !opts[:connection].respond_to?(:exchange)
        raise ArgumentError, 'secret_provider must be callable' unless opts[:secret_provider].nil? || opts[:secret_provider].respond_to?(:call)

        validate_secure_channel(opts) if opts.key?(:secure_channel)
      end

      private_class_method def self.validate_secure_channel(opts = {})
        channel = opts[:secure_channel]
        allowed = %i[scp kid kvn key_enc key_mac key_dek card_public_key ca_certificates card_certificates oce_private_key oce_certificates oce_kid oce_kvn]
        raise ArgumentError, 'secure_channel must be an explicit nonempty Hash of native key options' unless channel.is_a?(Hash) && !channel.empty? && (channel.keys - allowed).empty?
        raise ArgumentError, 'secure_channel requires an explicit scp protocol and integer kvn' unless %i[scp03 scp11a scp11b scp11c].include?(channel[:scp]) && channel[:kvn].is_a?(Integer) && channel[:kvn].between?(0, 255)

        Protocol.require_confirm(opts)
        return unless channel[:scp] == :scp03

        %i[key_enc key_mac].each do |key|
          raise ArgumentError, 'SCP03 requires explicit 16-byte in-memory keys' unless channel[key].is_a?(String) && channel[key].bytesize == 16
        end
      end

      private_class_method def self.validate_args(opts = {})
        args = opts[:args]
        raise ArgumentError, 'args must be a bounded nonempty Array of control-free Strings' unless args.is_a?(Array) && args.length.between?(1, 256) && args.all? { |value| value.is_a?(String) && !value.empty? && value.valid_encoding? && !value.b.match?(/[\x00-\x1f\x7f]/) } && args.sum(&:bytesize) <= 65_536

        args.map(&:dup)
      end

      private_class_method def self.validate_command(opts = {})
        grammar = COMMANDS[opts[:path]]
        return unless grammar

        parsed = Protocol.parse_args(args: opts[:args].drop(opts[:path].split.length), flags: grammar[1], values: grammar[2])
        maximum = { 'sd keys import' => 2, 'oath accounts import' => 0 }.fetch(opts[:path], grammar[0])
        raise ArgumentError, 'Unexpected or secret positional argument; supply credentials in memory' if parsed[:positionals].length > maximum
      end
    end
  end
end
