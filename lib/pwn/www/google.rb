# frozen_string_literal: true

module PWN
  module WWW
    # This plugin supports Google actions.
    module Google
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Google.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || :tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser_obj.goto('https://www.google.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Google.search(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   q: 'required - search string'
      # )

      public_class_method def self.search(opts = {})
        browser_obj = opts[:browser_obj]
        q = opts[:q].to_s

        browser_obj.text_field(name: 'q').wait_until(&:present?).set(q)
        browser_obj.button(text: 'Google Search').click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Google.search_linkedin_for_employees_by_company(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   company: 'required - company string'
      # )

      public_class_method def self.search_linkedin_for_employees_by_company(opts = {})
        browser_obj = opts[:browser_obj]
        company = opts[:company].to_s.scrub
        q = "site:linkedin.com inurl:in intext:\"#{company}\""

        browser_obj.text_field(name: 'q').wait_until(&:present?).set(q)
        browser_obj.button(text: 'Google Search').click!
        sleep 3 # Cough: <hack>

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Google.close(
      #   browser_obj: 'required - browser_obj returned from #open method',
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
            browser_type: 'optional :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port || :tor'
          )
          puts browser_obj.public_methods

          browser_obj = #{self}.search(
            browser_obj: 'required - browser_obj returned from #open method',
            q: 'required - search string'
          )

          browser_obj = #{self}.search_linkedin_for_employees_by_company(
            browser_obj: 'required - browser_obj returned from #open method',
            company: 'required - company string'
          )

          browser_obj = #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method'
          )

          #{self}.authors
        "
      end
    end
  end
end
