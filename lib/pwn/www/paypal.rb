# frozen_string_literal: true

require 'yaml'

module PWN
  module WWW
    # This plugin supports paypal.com actions.
    module Paypal
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Paypal.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://www.paypal.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Paypal.signup(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   first_name: 'required - first name',
      #   last_name: 'required - last name',
      #   address: 'required - address',
      #   city: 'required - city',
      #   state: 'required - state abbreviation',
      #   zip_code: 'required - zip code',
      #   mobile_phone: 'required - mobile phone',
      #   username: 'required - username (email address)',
      #   password: 'optional - passwd (will prompt if blank)',
      # )

      public_class_method def self.signup(opts = {})
        browser_obj = opts[:browser_obj]
        first_name = opts[:first_name].to_s.scrub.strip.chomp
        last_name = opts[:last_name].to_s.scrub.strip.chomp
        address = opts[:address].to_s.scrub.strip.chomp
        city = opts[:city].to_s.scrub.strip.chomp
        state = opts[:state].to_s.scrub.strip.chomp
        zip_code = opts[:zip_code].to_s.scrub.strip.chomp
        mobile_phone = opts[:mobile_phone].to_s.scrub.strip.chomp
        username = opts[:username].to_s.scrub.strip.chomp
        password = opts[:password]

        browser = browser_obj[:browser]

        if password.nil?
          password = PWN::Plugins::AuthenticationHelper.mask_password
        else
          password = opts[:password].to_s.scrub.strip.chomp
        end
        mfa = opts[:mfa]

        browser.goto('https://www.paypal.com/signup/account')

        browser.text_field(id: 'email').wait_until(&:present?).set(username)
        browser.text_field(id: 'password').wait_until(&:present?).set(password)
        browser.text_field(id: 'confirmPassword').wait_until(&:present?).set(password)
        browser.button(id: '_eventId_personal').wait_until(&:present?).click!
        browser.text_field(id: 'firstName').wait_until(&:present?).set(first_name)
        browser.text_field(id: 'lastName').wait_until(&:present?).set(last_name)
        browser.text_field(id: 'address1').wait_until(&:present?).set(address)
        browser.text_field(id: 'city').wait_until(&:present?).set(city)
        browser.select(id: 'state').wait_until(&:present?).select_value(state)
        browser.text_field(id: 'postalCode').wait_until(&:present?).set(zip_code)
        browser.text_field(id: 'phoneNumber').wait_until(&:present?).set(mobile_phone)
        browser.span(index: 7).wait_until(&:present?).click! # Agree to ToS
        browser.button(id: 'submitBtn').wait_until(&:present?).click!

        puts "Confirmation email sent to: #{username}"

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Paypal.login(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   username: 'required - username (email address)',
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

        browser.goto('https://www.paypal.com/signin')

        browser.text_field(id: 'email').wait_until(&:present?).set(username)
        browser.text_field(id: 'password').wait_until(&:present?).set(password)
        browser.button(id: 'btnLogin').click!

        if mfa
          # Send code to SMS
          browser.button(id: 'btnSelectSoftToken').wait_until(&:present?).click!
          until browser.url == 'https://www.paypal.com/myaccount/home'
            browser.text_field(id: 'security-code').wait_until(&:present?).set(PWN::Plugins::AuthenticationHelper.mfa(prompt: 'enter mfa token'))
            browser.button(id: 'btnCodeSubmit').click!
            sleep 3
          end
          print "\n"
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Paypal.logout(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.logout(opts = {})
        browser_obj = opts[:browser_obj]

        browser = browser_obj[:browser]
        browser.link(index: 13).wait_until(&:present?).click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Paypal.close(
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
          browser = browser_obj[:browser]
          puts browser.public_methods

          browser_obj = #{self}.signup(
            browser_obj: 'required - browser_obj returned from #open method',
            first_name: 'required - first name',
            last_name: 'required - last name',
            address: 'required - address',
            city: 'required - city',
            state: 'required - state abbreviation',
            zip_code: 'required - zip code',
            mobile_phone: 'required - mobile phone',
            username: 'required - username (email address)',
            password: 'optional - passwd (will prompt if blank)',
          )

          browser_obj = #{self}.login(
            browser_obj: 'required - browser_obj returned from #open method',
            username: 'required - username (email address)',
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
