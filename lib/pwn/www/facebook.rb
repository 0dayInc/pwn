# frozen_string_literal: true

require 'yaml'

module PWN
  module WWW
    # This plugin supports facebook.com actions.
    module Facebook
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Facebook.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || :tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser_obj.goto('https://www.facebook.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Facebook.login(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   username: 'required - username',
      #   password: 'optional - passwd (will prompt if blank)'
      # )

      public_class_method def self.login(opts = {})
        browser_obj = opts[:browser_obj]
        username = opts[:username].to_s.scrub.strip.chomp
        password = opts[:password]

        if password.nil?
          password = PWN::Plugins::AuthenticationHelper.mask_password
        else
          password = opts[:password].to_s.scrub.strip.chomp
        end

        browser_obj.goto('https://www.facebook.com/login.php')

        browser_obj.text_field(id: 'email').wait_until(&:present?).set(username)
        browser_obj.text_field(id: 'pass').wait_until(&:present?).set(password)
        browser_obj.button(id: 'loginbutton').click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Facebook.logout(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.logout(opts = {})
        browser_obj = opts[:browser_obj]
        browser_obj.div(id: 'logoutMenu').wait_until(&:present?).click!
        browser_obj.span(text: 'Log Out', class: '_54nh').click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Facebook.close(
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

      # Author(s):: 0day Inc. <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc. <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          browser_obj = #{self}.open(
            browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port || :tor'
          )
          puts browser_obj.public_methods

          browser_obj = #{self}.login(
            browser_obj: 'required - browser_obj returned from #open method',
            username: 'required - username',
            password: 'optional - passwd (will prompt if blank),
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
