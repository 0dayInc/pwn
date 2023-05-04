# frozen_string_literal: true

require 'ipaddress'
require 'nokogiri'

module PWN
  module WWW
    # This plugin supports Checkip actions.
    module Checkip
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Checkip.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || :tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser_obj.goto('http://checkip.amazonaws.com')
        public_ip_address = Nokogiri::HTML.parse(browser_obj.html).xpath('//pre').text.chomp
        puts "PUBLIC IP: #{public_ip_address}"

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::Checkip.close(
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

          browser_obj = #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method',
          )

          #{self}.authors
        "
      end
    end
  end
end
