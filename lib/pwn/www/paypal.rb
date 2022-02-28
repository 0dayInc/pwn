# frozen_string_literal: true

require 'yaml'

module PWN
  module WWW
    # This plugin supports paypal.com actions.
    module Paypal
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Paypal.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port',
      #   with_tor: 'optional - boolean (defaults to false)'
      # )

      public_class_method def self.open(opts = {})
        browser_type = if opts[:browser_type].nil?
                         :firefox
                       else
                         opts[:browser_type]
                       end

        proxy = opts[:proxy].to_s unless opts[:proxy].nil?

        with_tor = if opts[:with_tor]
                     true
                   else
                     false
                   end

        if proxy
          if with_tor
            browser_obj = PWN::Plugins::TransparentBrowser.open(
              browser_type: browser_type,
              proxy: proxy,
              with_tor: with_tor
            )
          else
            browser_obj = PWN::Plugins::TransparentBrowser.open(
              browser_type: browser_type,
              proxy: proxy
            )
          end
        else
          browser_obj = PWN::Plugins::TransparentBrowser.open(
            browser_type: browser_type
          )
        end

        browser_obj.goto('https://www.paypal.com')

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

        if password.nil?
          password = PWN::Plugins::AuthenticationHelper.mask_password
        else
          password = opts[:password].to_s.scrub.strip.chomp
        end
        mfa = opts[:mfa]

        browser_obj.goto('https://www.paypal.com/signup/account')

        browser_obj.text_field(id: 'email').wait_until(&:present?).set(username)
        browser_obj.text_field(id: 'password').wait_until(&:present?).set(password)
        browser_obj.text_field(id: 'confirmPassword').wait_until(&:present?).set(password)
        browser_obj.button(id: '_eventId_personal').wait_until(&:present?).click
        browser_obj.text_field(id: 'firstName').wait_until(&:present?).set(first_name)
        browser_obj.text_field(id: 'lastName').wait_until(&:present?).set(last_name)
        browser_obj.text_field(id: 'address1').wait_until(&:present?).set(address)
        browser_obj.text_field(id: 'city').wait_until(&:present?).set(city)
        browser_obj.select(id: 'state').wait_until(&:present?).select_value(state)
        browser_obj.text_field(id: 'postalCode').wait_until(&:present?).set(zip_code)
        browser_obj.text_field(id: 'phoneNumber').wait_until(&:present?).set(mobile_phone)
        browser_obj.span(index: 7).wait_until(&:present?).click # Agree to ToS
        browser_obj.button(id: 'submitBtn').wait_until(&:present?).click

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

        if password.nil?
          password = PWN::Plugins::AuthenticationHelper.mask_password
        else
          password = opts[:password].to_s.scrub.strip.chomp
        end
        mfa = opts[:mfa]

        browser_obj.goto('https://www.paypal.com/signin')

        browser_obj.text_field(id: 'email').wait_until(&:present?).set(username)
        browser_obj.text_field(id: 'password').wait_until(&:present?).set(password)
        browser_obj.button(id: 'btnLogin').wait_until(&:present?).click

        if mfa
          # Send code to SMS
          browser_obj.button(id: 'btnSelectSoftToken').wait_until(&:present?).click
          until browser_obj.url == 'https://www.paypal.com/myaccount/home'
            browser_obj.text_field(id: 'security-code').wait_until(&:present?).set(PWN::Plugins::AuthenticationHelper.mfa(prompt: 'enter mfa token'))
            browser_obj.button(id: 'btnCodeSubmit').wait_until(&:present?).click
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
        browser_obj.link(index: 13).wait_until(&:present?).click

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

      # Author(s):: Jacob Hoopes <jake.hoopes@gmail.com>

      public_class_method def self.authors
        "AUTHOR(S):
          Jacob Hoopes <jake.hoopes@gmail.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          browser_obj = #{self}.open(
            browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port',
            with_tor: 'optional - boolean (defaults to false)'
          )
          puts browser_obj.public_methods

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
