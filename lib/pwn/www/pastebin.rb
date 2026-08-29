# frozen_string_literal: true

module PWN
  module WWW
    # This plugin supports Pastebin actions.
    module Pastebin
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Pastebin.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://pastebin.com')

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

        browser = browser_obj[:browser]
        browser.goto('http://lw4ipk5choakk5ze.onion')

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

          # Run onion and return its result
          #{self}.onion(
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
