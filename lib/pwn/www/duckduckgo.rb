# frozen_string_literal: true

module PWN
  module WWW
    # This plugin supports Duckduckgo actions.
    module Duckduckgo
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Duckduckgo.open(
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
              with_tor: true
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
        browser_obj.goto('https://duckduckgo.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Duckduckgo.search(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   q: 'required - search string'
      # )

      public_class_method def self.search(opts = {})
        browser_obj = opts[:browser_obj]
        q = opts[:q].to_s

        browser_obj.text_field(name: 'q').wait_until(&:present?).set(q)
        if browser_obj.url == 'https://duckduckgo.com/' || browser_obj.url == 'http://3g2upl4pq6kufc4m.onion/'
          browser_obj.button(id: 'search_button_homepage').wait_until(&:present?).click
        else
          browser_obj.button(id: 'search_button').wait_until(&:present?).click
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Duckduckgo.onion(
      #   browser_obj: 'required - browser_obj returned from #open method',
      # )

      public_class_method def self.onion(opts = {})
        browser_obj = opts[:browser_obj]
        browser_obj.goto('http://3g2upl4pq6kufc4m.onion')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Duckduckgo.close(
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

      # Author(s):: 0day Inc <request.pentest@0dayinc.com>

      public_class_method def self.authors
        "AUTHOR(S):
          0day Inc <request.pentest@0dayinc.com>
        "
      end

      # Display Usage for this Module

      public_class_method def self.help
        puts "USAGE:
          browser_obj = #{self}.open(
            browser_type: 'optional :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port',
            with_tor: 'optional - boolean (defaults to false)'
          )
          puts browser_obj.public_methods

          browser_obj = #{self}.search(
            browser_obj: 'required - browser_obj returned from #open method',
            q: 'required search string'
          )

          browser_obj = #{self}.onion(
            browser_obj: 'required - browser_obj returned from #open method'
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
