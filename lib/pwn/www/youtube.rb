# frozen_string_literal: true

module PWN
  module WWW
    # This plugin supports Youtube actions.
    module Youtube
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Youtube.open(
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
        browser_obj.goto('https://www.youtube.com')

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

        browser_obj.text_field(name: 'search_query').wait_until(&:present?).set(q)
        browser_obj.button(id: 'search-btn').wait_until(&:present?).click

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Youtube.close(
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
          browser_obj =#{self}.open(
            browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port',
            with_tor: 'optional - boolean (defaults to false)'
          )
          puts 'browser_obj.public_methods'

          browser_obj =#{self}.search(
            browser_obj: 'required - browser_obj returned from #open method',
            q: 'required search string'
          )

          browser_obj =#{self}.close(
            browser_obj: 'required - browser_obj returned from #open method',
          )

          #{self}.authors
        "
      end
    end
  end
end
