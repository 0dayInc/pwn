# frozen_string_literal: true

module PWN
  module WWW
    # This plugin supports Duckduckgo actions.
    module Duckduckgo
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Duckduckgo.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://duckduckgo.com')

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

        browser = browser_obj[:browser]
        browser.text_field(name: 'q').wait_until(&:present?).set(q)
        if browser.url == 'https://duckduckgo.com/' ||
           browser.url == 'http://3g2upl4pq6kufc4m.onion/'

          browser.button(id: 'search_button_homepage').click!
        else
          browser.button(id: 'search_button').click!
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

        browser = browser_obj[:browser]
        browser.goto('http://3g2upl4pq6kufc4m.onion')

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
            proxy: 'optional - scheme://proxy_host:port || tor'
          )
          browser = browser_obj[:browser]
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
