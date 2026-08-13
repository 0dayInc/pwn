# frozen_string_literal: true

require 'yaml'

module PWN
  module WWW
    # This plugin supports github.com actions.
    module GitHub
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::GitHub.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://github.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::GitHub.login(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   username: 'required - username',
      #   password: 'optional - passwd (will prompt if blank)',
      #   mfa: 'optional - MFA / TOTP token string, or true to prompt (defaults to false)',
      #   mfa_token: 'optional - MFA / TOTP token used to reach a post-authenticated state'
      # )

      public_class_method def self.login(opts = {})
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
        mfa_token = opts[:mfa_token].to_s.scrub.strip.chomp
        mfa_token = mfa.to_s.scrub.strip.chomp if mfa_token.empty? && mfa.is_a?(String)

        browser.goto('https://github.com/login')

        browser.text_field(name: 'login').wait_until(&:present?).set(username)
        browser.text_field(name: 'password').wait_until(&:present?).set(password)
        browser.input(name: 'commit').click!

        if mfa || !mfa_token.empty?
          until browser.url == 'https://github.com/' ||
                browser.url.include?('https://github.com/dashboard') ||
                (
                  browser.url.start_with?('https://github.com/') &&
                  !browser.url.include?('/login') &&
                  !browser.url.include?('/session')
                )

            token = if mfa_token.empty?
                      PWN::Plugins::AuthenticationHelper.mfa(prompt: 'enter mfa token')
                    else
                      consumed = mfa_token
                      mfa_token = ''
                      consumed
                    end

            if browser.text_field(name: 'app_otp').exist?
              browser.text_field(name: 'app_otp').wait_until(&:present?).set(token)
            elsif browser.text_field(id: 'app_totp').exist?
              browser.text_field(id: 'app_totp').wait_until(&:present?).set(token)
            elsif browser.text_field(name: 'otp').exist?
              browser.text_field(name: 'otp').wait_until(&:present?).set(token)
            else
              browser.text_field(name: 'sms_otp').wait_until(&:present?).set(token)
            end

            if browser.input(name: 'commit').exist?
              browser.input(name: 'commit').click!
            elsif browser.button(type: 'submit').exist?
              browser.button(type: 'submit').click!
            end
            sleep 3
          end
          print "\n"
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::GitHub.logout(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.logout(opts = {})
        browser_obj = opts[:browser_obj]

        browser = browser_obj[:browser]
        browser.goto('https://github.com/logout')
        if browser.input(name: 'commit').exist?
          browser.input(name: 'commit').wait_until(&:present?).click!
        elsif browser.button(name: 'commit').exist?
          browser.button(name: 'commit').wait_until(&:present?).click!
        else
          browser.button(text: 'Sign out').wait_until(&:present?).click!
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::GitHub.close(
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
          browser_obj = #{self}.open(
            browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port || tor'
          )

          browser_obj = #{self}.login(
            browser_obj: 'required - browser_obj returned from #open method',
            username: 'required - username',
            password: 'optional - passwd (will prompt if blank),
            mfa: 'optional - MFA / TOTP token string, or true to prompt (defaults to false)',
            mfa_token: 'optional - MFA / TOTP token used to reach a post-authenticated state'
          )

          browser_obj = #{self}.logout(
            browser_obj: 'required - browser_obj returned from #open method'
          )

          #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method'
          )

          #{self}.authors
        "
      end
    end
  end
end
