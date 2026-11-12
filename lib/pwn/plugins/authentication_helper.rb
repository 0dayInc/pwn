# frozen_string_literal: true

require 'tty-prompt'

module PWN
  module Plugins
    # This plugin is used to assist in masking a password when entered in via
    # STDIN to prevent would-be shoulder surfers from obtaining password
    # information.  This plugin is useful when demonstrating the functionality
    # of other SP plugins/modules. MFA can explicitly select a YubiKey OATH
    # account without storing its secret; device failures never fall back to a prompt.
    # Native OATH requires explicit confirm: true because HOTP advances counters
    # and password-protected accounts can require authentication. Passwords and
    # secret providers remain in memory; no automatic deletion or repair occurs.
    module AuthenticationHelper
      # Supported Method Parameters::
      # PWN::Plugins::AuthenticationHelper.username(
      #   prompt: 'optional - string to display at prompt (Default: Username)'
      # )

      public_class_method def self.username(opts = {})
        prompt = opts[:prompt] ||= 'Username'
        user = TTY::Prompt.new.ask("#{prompt}: ")
        user.to_s.strip.chomp.scrub
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::AuthenticationHelper.mask_password(
      #   prompt: 'optional - string to display at prompt (Default: Password)'
      # )

      public_class_method def self.mask_password(opts = {})
        prompt = opts[:prompt] ||= 'Password'

        pass = TTY::Prompt.new.mask("#{prompt}: ")
        pass.to_s.strip.chomp.scrub
      rescue Interrupt
        puts "#{self}.#{__method__} => Goodbye."
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::AuthenticationHelper.mfa(
      #   prompt: 'optional - string to display at prompt (Default: MFA Token)',
      #   yubikey: 'optional - Hash selecting an exact OATH account (required :account and literal :confirm true); optional :serial exact decimal String, :reader or :device_path nonempty control-free String, :connection native exchange object, :timeout finite positive seconds (default 30), in-memory :password or callable :secret_provider; serial/reader and reader/device_path are mutually exclusive; no OTP slot; explicit mfa/mfa_token values conflict'
      # )

      public_class_method def self.mfa(opts = {})
        validate_mfa_options(opts)
        return PWN::Plugins::YubiKey.oath_code(opts[:yubikey]) unless opts[:yubikey].nil?

        prompt = opts[:prompt] ||= 'MFA Token'

        mfa = TTY::Prompt.new.ask("#{prompt}: ")
        mfa.to_s.strip.chomp.scrub
      rescue Interrupt
        raise unless opts[:yubikey].nil?

        puts "#{self}.#{__method__} => Goodbye."
      rescue StandardError => e
        raise e
      end

      # Validate MFA source selection before login without touching a device.
      public_class_method def self.validate_mfa_options(opts = {})
        yubikey = opts[:yubikey]
        return opts if yubikey.nil?

        raise ArgumentError, 'yubikey must be a Hash with an exact OATH account' unless yubikey.is_a?(Hash)
        raise ArgumentError, 'yubikey slot is not an OATH option; use the exact account name' if yubikey.key?(:slot) || yubikey.key?('slot')

        account = yubikey[:account]
        raise ArgumentError, 'yubikey account must be a nonempty exact OATH name without control characters' unless account.is_a?(String) && account.valid_encoding? && !account.strip.empty? && !account.match?(/[[:cntrl:]]/)

        raise ArgumentError, 'yubikey cannot be combined with an explicit mfa or mfa_token' if !opts[:mfa_token].to_s.strip.empty? || (opts[:mfa].is_a?(String) && !opts[:mfa].strip.empty?)
        raise ArgumentError, 'yubikey requires confirm: true: HOTP advances counters and protected OATH accounts may require authentication' unless yubikey[:confirm] == true

        validate_native_yubikey_options(yubikey: yubikey)
        opts
      end

      private_class_method def self.validate_native_yubikey_options(opts = {})
        selector = opts[:yubikey]
        allowed = %i[account confirm serial reader device_path connection timeout password secret_provider]
        raise ArgumentError, 'Unknown yubikey OATH selector option' unless (selector.keys - allowed).empty?

        serial = selector[:serial]
        raise ArgumentError, 'yubikey serial must be an exact decimal String' unless serial.nil? || (serial.is_a?(String) && serial.valid_encoding? && serial.match?(/\A[0-9]+\z/))

        timeout = selector[:timeout]
        raise ArgumentError, 'yubikey timeout must be finite positive seconds' unless timeout.nil? || ((timeout.is_a?(Integer) || timeout.is_a?(Float)) && timeout.finite? && timeout.positive?)

        %i[reader device_path].each do |field|
          name = selector[field]
          raise ArgumentError, "yubikey #{field} must be a nonempty String without control characters" unless name.nil? || (name.is_a?(String) && name.valid_encoding? && !name.empty? && !name.match?(/[[:cntrl:]]/))
        end
        raise ArgumentError, 'yubikey serial and reader selectors are mutually exclusive' if !serial.nil? && !selector[:reader].nil?
        raise ArgumentError, 'yubikey reader and device_path selectors are mutually exclusive' if !selector[:reader].nil? && !selector[:device_path].nil?

        connection = selector[:connection]
        raise ArgumentError, 'yubikey connection must respond to exchange' unless connection.nil? || connection.respond_to?(:exchange)

        password = selector[:password]
        raise ArgumentError, 'yubikey password must be a nonempty in-memory String' unless password.nil? || (password.is_a?(String) && !password.empty?)

        provider = selector[:secret_provider]
        raise ArgumentError, 'yubikey secret_provider must respond to call' unless provider.nil? || provider.respond_to?(:call)

        selector
      end

      # Author(s):: 0day Inc. <support@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <support@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          # Run username and return its result
          #{self}.username(
            prompt: 'optional - string to display at prompt (Default: Username)'
          )
          # Run mask password and return its result
          #{self}.mask_password(
            prompt: 'optional - string to display at prompt (Default: Password)'
          )

          # Return a manual MFA token or exact-account YubiKey OATH digits without logging them.
          #{self}.mfa(
            prompt: 'optional - string to display at the manual prompt (Default: MFA Token)',
            yubikey: 'optional - Hash selecting an exact OATH account (required :account and literal :confirm true); optional :serial exact decimal String, :reader or :device_path nonempty control-free String, :connection native exchange object, :timeout finite positive seconds (default 30), in-memory :password or callable :secret_provider; serial/reader and reader/device_path are mutually exclusive; no OTP slot; explicit mfa/mfa_token values conflict'
          )
          # Example yubikey: { account: 'EXACT_OATH_NAME', confirm: true, serial: '123456', timeout: 30 }
          # Explicit consent is required: HOTP advances counters and protected OATH accounts may require authentication. No automatic repair or deletion occurs.
          # The account name is passed unchanged. Device failures and cancellation propagate; no manual fallback.
          # OATH credentials are distinct from OTP slots, SMS codes, and FIDO2/WebAuthn security keys.

          # Validate MFA source selection before login without prompting or accessing a device; return opts.
          #{self}.validate_mfa_options(
            yubikey: 'optional - Hash selecting an exact OATH account (required :account and literal :confirm true); optional :serial exact decimal String, :reader or :device_path nonempty control-free String, :connection native exchange object, :timeout finite positive seconds (default 30), in-memory :password or callable :secret_provider; serial/reader and reader/device_path are mutually exclusive; no OTP slot; explicit mfa/mfa_token values conflict',
            mfa: 'optional - browser MFA flag or explicit token string; a nonblank token conflicts with YubiKey',
            mfa_token: 'optional - explicit browser MFA token; a nonblank value conflicts with YubiKey'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
