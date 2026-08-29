# frozen_string_literal: true

require 'yaml'

module PWN
  module WWW
    # This plugin supports tradingview.com actions.
    module TradingView
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::TradingView.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://tradingview.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::TradingView.login(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   username: 'required - username',
      #   password: 'optional - passwd (will prompt if blank)'
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

        browser.goto('https://tradingview.com')

        browser.button(index: 3).wait_until(&:present?).click
        browser.div(text: 'Sign in').wait_until(&:present?).click
        browser.span(text: 'Email').wait_until(&:present?).click
        browser.text_field(name: 'username').wait_until(&:present?).set(username)
        browser.text_field(name: 'password').wait_until(&:present?).set(password)
        browser.button(text: 'Sign in').click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::TradingView.logout(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.logout(opts = {})
        browser_obj = opts[:browser_obj]

        browser = browser_obj[:browser]
        browser.button(index: 4).wait_until(&:present?).click
        browser.div(text: 'Sign Out').wait_until(&:present?).click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::TradingView.close(
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

          # Run login and return its result
          #{self}.login(
            browser_obj: 'required - browser_obj returned from #open method',
            username: 'required - username value consumed by #login',
            password: 'optional - passwd (will prompt if blank)'
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
