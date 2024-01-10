# frozen_string_literal: true

module PWN
  module WWW
    # This plugin supports Torch (Tor Search Engine) actions.
    module Torch
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Torch.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('http://www.torchtorsearch.com')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Torch.open(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   q: 'required search string'
      # )

      public_class_method def self.search(opts = {})
        browser_obj = opts[:browser_obj]
        q = opts[:q].to_s

        browser = browser_obj[:browser]
        browser.text_field(name: 'q').wait_until(&:present?).set(q)
        browser.button(name: 'cmd').click!

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Torch.onion(
      #   browser_obj: 'required - browser_obj returned from #open method'
      # )

      public_class_method def self.onion
        browser_obj = opts[:browser_obj]

        browser = browser_obj[:browser]
        browser.goto('http://xmh57jrzrnw6insl.onion')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Torch.close(
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

          browser_obj = #{self}.open(
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
