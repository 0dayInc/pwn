# frozen_string_literal: true

module PWN
  module WWW
    # This plugin supports Pastebin actions.
    module Pastebin
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Pastebin.open(
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
        browser_obj.goto('https://pastebin.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Pastebin.onion(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.onion(opts = {})
        browser_obj = opts[:browser_obj]
        browser_obj.goto('http://lw4ipk5choakk5ze.onion')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Pastebin.close(
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
            browser_type: 'optional :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port',
            with_tor: 'optional - boolean (defaults to false)'
          )
          puts browser_obj.public_methods

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
