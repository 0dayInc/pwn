# frozen_string_literal: true

require 'yaml'

module PWN
  module WWW
    # This plugin supports platform.synack.com actions.
    # YubiKey OATH MFA requires explicit confirm: true because HOTP advances counters
    # and protected OATH accounts may require authentication; no automatic repair or deletion occurs.
    module Synack
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Synack.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://www.synack.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Synack.login(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   username: 'required - username',
      #   password: 'optional - passwd (will prompt if blank)',
      #   mfa: 'optional - if true prompt for mfa token (defaults to false)',
      #   yubikey: 'optional - Hash selecting an exact OATH account (required :account and literal :confirm true); optional :serial exact decimal String, :reader or :device_path nonempty control-free String, :connection native exchange object, :timeout finite positive seconds (default 30), in-memory :password or callable :secret_provider; serial/reader and reader/device_path are mutually exclusive; no OTP slot; explicit mfa/mfa_token values conflict'
      # )

      public_class_method def self.login(opts = {})
        PWN::Plugins::AuthenticationHelper.validate_mfa_options(opts)
        yubikey = opts[:yubikey]
        browser_obj = opts[:browser_obj]
        username = opts[:username].to_s.scrub.strip.chomp
        password = opts[:password]

        browser = browser_obj[:browser]

        if password.nil?
          password = PWN::Plugins::AuthenticationHelper.mask_password
        else
          password = opts[:password].to_s.scrub.strip.chomp
        end
        mfa = opts[:mfa]

        browser.goto('https://login.synack.com')

        browser.text_field(name: 'email').wait_until(&:present?).set(username)
        browser.text_field(name: 'password').wait_until(&:present?).set(password)
        browser.button(class: 'btn').click!

        if mfa || !yubikey.nil?
          until browser.url.include?('https://platform.synack.com')
            browser.text_field(name: 'authy_token').wait_until(&:present?).set(PWN::Plugins::AuthenticationHelper.mfa(prompt: 'enter mfa token', yubikey: yubikey))
            browser.button(class: 'btn').click!
            sleep 3
          end
          print "\n"
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Synack.logout(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.logout(opts = {})
        browser_obj = opts[:browser_obj]

        browser = browser_obj[:browser]
        browser.img(class: 'navbar-avatar-img').wait_until(&:present?).click!
        browser.button(text: 'Logout').wait_until(&:present?).click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Synack.close(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.close(opts = {})
        browser_obj = opts[:browser_obj]
        PWN::Plugins::TransparentBrowser.close(
          browser_obj: browser_obj
        )
      rescue StandardError => e
        raise e
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
          # Open a session or connection and return a handle.
          #{self}.open(
            browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port || tor'
          )

          # Log in with manual MFA or explicitly selected YubiKey OATH.
          # YubiKey enables MFA even when mfa is false; failures never fall back to a prompt.
          # Configure the service for an authenticator challenge, not SMS.
          # Example yubikey: { account: 'EXACT_OATH_NAME', confirm: true, serial: '123456', timeout: 30 }
          # Explicit consent is required: HOTP advances counters and protected OATH accounts may require authentication; no automatic repair or deletion occurs.
          # Reject conflicting explicit tokens before any login action.
          #{self}.login(
            browser_obj: 'required - browser_obj returned from #open method',
            username: 'required - username value consumed by #login',
            password: 'optional - passwd (will prompt if blank)',
            mfa: 'optional - if true prompt for mfa token (defaults to false)',
            yubikey: 'optional - Hash selecting an exact OATH account (required :account and literal :confirm true); optional :serial exact decimal String, :reader or :device_path nonempty control-free String, :connection native exchange object, :timeout finite positive seconds (default 30), in-memory :password or callable :secret_provider; serial/reader and reader/device_path are mutually exclusive; no OTP slot; explicit mfa/mfa_token values conflict'
          )

          # Run logout and return its result
          #{self}.logout(
            browser_obj: 'required - browser_obj returned from #open method'
          )

          # Close a session previously returned by #open.
          #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
