# frozen_string_literal: true

require 'yaml'

module PWN
  module WWW
    # This plugin supports bugcrowd.com actions.
    module BugCrowd
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::BugCrowd.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser_obj.goto('https://bugcrowd.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::BugCrowd.login(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   username: 'required - username',
      #   password: 'optional - passwd (will prompt if blank)',
      #   mfa: 'optional - if true prompt for mfa token (defaults to false)'
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
        mfa = opts[:mfa]

        browser_obj.goto('https://bugcrowd.com/user/sign_in')

        browser_obj.text_field(id: 'user_email').wait_until(&:present?).set(username)
        browser_obj.text_field(id: 'user_password').wait_until(&:present?).set(password)
        browser_obj.button(name: 'button').click!

        if mfa
          until browser_obj.url == 'https://bugcrowd.com/programs'
            browser_obj.text_field(name: 'otp_attempt').wait_until(&:present?).set(PWN::Plugins::AuthenticationHelper.mfa(prompt: 'enter mfa token'))
            browser_obj.button(name: 'commit').click!
            sleep 3
          end
          print "\n"
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::BugCrowd.logout(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.logout(opts = {})
        browser_obj = opts[:browser_obj]
        browser_obj.li(class: 'dropdown-hover').wait_until(&:present?).hover
        browser_obj.link(class: 'signout_link').wait_until(&:present?).click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::BugCrowd.close(
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
            proxy: 'optional - scheme://proxy_host:port || tor'
          )
          puts browser_obj.public_methods

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
