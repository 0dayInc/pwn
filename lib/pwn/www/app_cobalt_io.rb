# frozen_string_literal: true

require 'yaml'

module PWN
  module WWW
    # This plugin supports app.cobalt.io actions.
    module AppCobaltIO
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::AppCobaltIO.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://app.cobalt.io')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::AppCobaltIO.login(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   username: 'required - username',
      #   password: 'optional - passwd (will prompt if blank)',
      #   mfa: 'optional - if true prompt for mfa token (defaults to false)'
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

        browser.goto('https://app.cobalt.io/users/sign_in')

        # id: 'user_email' doesn't work
        browser.text_field(index: 9).wait_until(&:present?).set(username)
        # id: 'user_password' doesn't work
        browser.text_field(index: 10).wait_until(&:present?).set(password)
        # name: 'commit' doesn't work
        browser.button(index: 6).click! # no name or id in button element

        if mfa
          until browser.url == 'https://app.cobalt.io/dashboard'
            browser.text_field(id: 'code').wait_until(&:present?).set(PWN::Plugins::AuthenticationHelper.mfa(prompt: 'enter mfa token'))
            browser.button(name: 'commit').click!
            sleep 3
          end
          print "\n"
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::AppCobaltIO.logout(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.logout(opts = {})
        browser_obj = opts[:browser_obj]

        browser = browser_obj[:browser]
        browser.li(class: 'user-dropdown').wait_until(&:present?).click!
        browser.link(index: 10).wait_until(&:present?).click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::AppCobaltIO.close(
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
            mfa: 'optional - if true prompt for mfa token (defaults to false)'
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
