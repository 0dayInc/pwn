# frozen_string_literal: true

module PWN
  module WWW
    # This plugin supports Wayback Machine actions.
    module WaybackMachine
      # Supported Method Parameters::
      # browser_obj = PWN::WWW::WaybackMachine.open(
      #   browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
      #   proxy: 'optional - scheme://proxy_host:port || tor'
      # )

      public_class_method def self.open(opts = {})
        browser_obj = PWN::Plugins::TransparentBrowser.open(opts)

        browser = browser_obj[:browser]
        browser.goto('https://web.archive.org')

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::WaybackMachine.search(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   q: 'required - search string'
      # )

      public_class_method def self.search(opts = {})
        browser_obj = opts[:browser_obj]
        q = opts[:q].to_s

        browser = browser_obj[:browser]
        browser.text_field(name: 'query').wait_until(&:present?).set(q).submit

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::WaybackMachine.timetravel(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   uri: 'required - URI (e.g. https://example.com)',
      #   date: 'optional - date in YYYYMMDD format (Defaults to today)'
      # )

      public_class_method def self.timetravel(opts = {})
        browser_obj = opts[:browser_obj]
        uri = opts[:uri].to_s
        date = opts[:date] ||= Time.now.strftime('%Y%m%d')

        browser = browser_obj[:browser]
        browser.goto("https://web.archive.org/web/#{date}/#{uri}")

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::WWW::WaybackMachine.close(
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
          browser_obj = #{self}.open(
            browser_type: 'optional - :firefox|:chrome|:ie|:headless (Defaults to :firefox)',
            proxy: 'optional - scheme://proxy_host:port || tor'
          )

          browser_obj = #{self}.search(
            browser_obj: 'required - browser_obj returned from #open method',
            q: 'required search string'
          )

          browser_obj = #{self}.timetravel(
            browser_obj: 'required - browser_obj returned from #open method',
            uri: 'required - URI (e.g. https://example.com)',
            date: 'optional - date in YYYYMMDD format (Defaults to today)'
          )

          browser_obj = #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method',
          )

          #{self}.authors
        "
      end
    end
  end
end
