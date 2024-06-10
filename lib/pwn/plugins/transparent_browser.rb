# frozen_string_literal: true

require 'watir'
require 'selenium/webdriver'
require 'selenium/devtools'
require 'rest-client'
require 'socksify'
require 'openssl'
require 'em/pure_ruby'
require 'faye/websocket'

module PWN
  module Plugins
    # This plugin rocks. Chrome, Firefox, headless, REST Client,
    # all from the comfort of one plugin.  Proxy support (e.g. Burp
    # Suite Professional) is completely available for all browsers
    # except for limited functionality within IE (IE has interesting
    # protections in place to prevent this).  This plugin also supports
    # taking screenshots :)
    module TransparentBrowser
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.open(
      #   browser_type: :firefox|:chrome|:headless|:rest|:websocket,
      #   proxy: 'optional - scheme://proxy_host:port || tor',
      #   with_devtools: 'optional - boolean (defaults to false)'
      # )

      public_class_method def self.open(opts = {})
        browser_type = opts[:browser_type]
        proxy = opts[:proxy].to_s unless opts[:proxy].nil?

        browser_obj = {}

        tor_obj = nil
        if opts[:proxy] == 'tor'
          tor_obj = PWN::Plugins::Tor.start
          proxy = "socks5://#{tor_obj[:ip]}:#{tor_obj[:port]}"
          browser_obj[:tor_obj] = tor_obj
        end

        opts[:with_devtools] ? (with_devtools = true) : (with_devtools = false)

        # Let's crank up the default timeout from 30 seconds to 15 min for slow sites
        Watir.default_timeout = 900

        args = []
        args.push('--start-maximized')
        args.push('--disable-notifications')

        unless browser_type == :rest
          logger = Selenium::WebDriver.logger
          logger.level = :error
        end

        case browser_type
        when :firefox
          this_profile = Selenium::WebDriver::Firefox::Profile.new

          # Increase Web Assembly Verbosity
          this_profile['javascript.options.wasm_verbose'] = true

          # Downloads reside in ~/Downloads
          this_profile['browser.download.folderList'] = 1
          this_profile['browser.helperApps.neverAsk.saveToDisk'] = 'application/pdf'

          # disable Firefox's built-in PDF viewer
          this_profile['pdfjs.disabled'] = true

          # disable Adobe Acrobat PDF preview plugin
          this_profile['plugin.scan.plid.all'] = false
          this_profile['plugin.scan.Acrobat'] = '99.0'

          # ensure localhost proxy capabilities are enabled
          this_profile['network.proxy.no_proxies_on'] = ''

          # allow scripts to run a bit longer
          # this_profile['dom.max_chrome_script_run_time'] = 180
          # this_profile['dom.max_script_run_time'] = 180

          # disable browser cache
          this_profile['browser.cache.disk.enable'] = false
          this_profile['browser.cache.disk_cache_ssl.enable'] = false
          this_profile['browser.cache.memory.enable'] = false
          this_profile['browser.cache.offline.enable'] = false
          this_profile['devtools.cache.disabled'] = true
          this_profile['dom.caches.enabled'] = false

          # caps = Selenium::WebDriver::Remote::Capabilities.firefox
          # caps[:acceptInsecureCerts] = true

          if proxy
            this_profile['network.proxy.type'] = 1
            this_profile['network.proxy.allow_hijacking_localhost'] = true
            if tor_obj
              this_profile['network.proxy.socks_version'] = 5
              this_profile['network.proxy.socks'] = tor_obj[:ip]
              this_profile['network.proxy.socks_port'] = tor_obj[:port]
            else
              this_profile['network.proxy.ftp'] = URI(proxy).host
              this_profile['network.proxy.ftp_port'] = URI(proxy).port
              this_profile['network.proxy.http'] = URI(proxy).host
              this_profile['network.proxy.http_port'] = URI(proxy).port
              this_profile['network.proxy.ssl'] = URI(proxy).host
              this_profile['network.proxy.ssl_port'] = URI(proxy).port
            end
          end

          args.push('--devtools') if with_devtools
          options = Selenium::WebDriver::Firefox::Options.new(
            args: args,
            accept_insecure_certs: true
          )
          options.profile = this_profile
          # driver = Selenium::WebDriver.for(:firefox, capabilities: options)
          driver = Selenium::WebDriver.for(:firefox, options: options)
          browser_obj[:browser] = Watir::Browser.new(driver)

        when :chrome
          this_profile = Selenium::WebDriver::Chrome::Profile.new
          this_profile['download.prompt_for_download'] = false
          this_profile['download.default_directory'] = '~/Downloads'

          if proxy
            args.push("--host-resolver-rules='MAP * 0.0.0.0 , EXCLUDE #{tor_obj[:ip]}'") if tor_obj
            args.push("--proxy-server=#{proxy}")
          end

          if with_devtools
            args.push('--auto-open-devtools-for-tabs')
            args.push('--disable-hang-monitor')
          end

          options = Selenium::WebDriver::Chrome::Options.new(
            args: args,
            accept_insecure_certs: true
          )

          options.profile = this_profile
          # driver = Selenium::WebDriver.for(:chrome, capabilities: options)
          driver = Selenium::WebDriver.for(:chrome, options: options)
          browser_obj[:browser] = Watir::Browser.new(driver)

        when :headless, :headless_firefox
          this_profile = Selenium::WebDriver::Firefox::Profile.new

          # Increase Web Assembly Verbosity
          this_profile['javascript.options.wasm_verbose'] = true

          # Downloads reside in ~/Downloads
          this_profile['browser.download.folderList'] = 1
          this_profile['browser.helperApps.neverAsk.saveToDisk'] = 'application/pdf'

          # disable Firefox's built-in PDF viewer
          this_profile['pdfjs.disabled'] = true

          # disable Adobe Acrobat PDF preview plugin
          this_profile['plugin.scan.plid.all'] = false
          this_profile['plugin.scan.Acrobat'] = '99.0'

          # ensure localhost proxy capabilities are enabled
          this_profile['network.proxy.no_proxies_on'] = ''

          # allow scripts to run a bit longer
          # this_profile['dom.max_chrome_script_run_time'] = 180
          # this_profile['dom.max_script_run_time'] = 180

          # disable browser cache
          this_profile['browser.cache.disk.enable'] = false
          this_profile['browser.cache.disk_cache_ssl.enable'] = false
          this_profile['browser.cache.memory.enable'] = false
          this_profile['browser.cache.offline.enable'] = false
          this_profile['devtools.cache.disabled'] = true
          this_profile['dom.caches.enabled'] = false

          # caps = Selenium::WebDriver::Remote::Capabilities.firefox
          # caps[:acceptInsecureCerts] = true

          if proxy
            this_profile['network.proxy.type'] = 1
            this_profile['network.proxy.allow_hijacking_localhost'] = true
            if tor_obj
              this_profile['network.proxy.socks_version'] = 5
              this_profile['network.proxy.socks'] = tor_obj[:ip]
              this_profile['network.proxy.socks_port'] = tor_obj[:port]
            else
              this_profile['network.proxy.ftp'] = URI(proxy).host
              this_profile['network.proxy.ftp_port'] = URI(proxy).port
              this_profile['network.proxy.http'] = URI(proxy).host
              this_profile['network.proxy.http_port'] = URI(proxy).port
              this_profile['network.proxy.ssl'] = URI(proxy).host
              this_profile['network.proxy.ssl_port'] = URI(proxy).port
            end
          end

          args.push('--headless')
          options = Selenium::WebDriver::Firefox::Options.new(
            args: args,
            accept_insecure_certs: true
          )

          options.profile = this_profile
          driver = Selenium::WebDriver.for(:firefox, options: options)
          browser_obj[:browser] = Watir::Browser.new(driver)

        when :headless_chrome
          this_profile = Selenium::WebDriver::Chrome::Profile.new
          this_profile['download.prompt_for_download'] = false
          this_profile['download.default_directory'] = '~/Downloads'

          args.push('--headless')

          if proxy
            args.push("--host-resolver-rules='MAP * 0.0.0.0 , EXCLUDE #{tor_obj[:ip]}'") if tor_obj
            args.push("--proxy-server=#{proxy}")
          end

          options = Selenium::WebDriver::Chrome::Options.new(
            args: args,
            accept_insecure_certs: true
          )

          options.profile = this_profile
          driver = Selenium::WebDriver.for(:chrome, options: options)
          browser_obj[:browser] = Watir::Browser.new(driver)

        when :rest
          browser_obj[:browser] = RestClient
          if proxy
            if tor_obj
              TCPSocket.socks_server = tor_obj[:ip]
              TCPSocket.socks_port = tor_obj[:port]
            else
              browser_obj[:browser].proxy = proxy
            end
          end

        when :websocket
          if proxy
            if tor_obj
              TCPSocket.socks_server = tor_obj[:ip]
              TCPSocket.socks_port = tor_obj[:port]
            end
            proxy_opts = { origin: proxy }
            tls_opts = { verify_peer: false }
            browser_obj[:browser] = Faye::WebSocket::Client.new(
              '',
              [],
              {
                tls: tls_opts,
                proxy: proxy_opts
              }
            )
          else
            browser_obj[:browser] = Faye::WebSocket::Client.new('')
          end
        else
          puts 'Error: browser_type only supports :firefox, :chrome, :headless, :rest, or :websocket'
          return nil
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::Plugins::TransparentBrowser.linkout(
      #   browser_obj: browser_obj1
      # )

      public_class_method def self.linkout(opts = {})
        browser_obj = opts[:browser_obj]

        browser_obj[:browser].links.each do |link|
          @@logger.info("#{link.text} => #{link.href}\n\n\n") unless link.text == ''
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::Plugins::TransparentBrowser.find_element_by_text(
      #   browser_obj: browser_obj1,
      #   text: 'required - text to search for in the DOM'
      # )

      public_class_method def self.find_element_by_text(opts = {})
        browser_obj = opts[:browser_obj]
        text = opts[:text].to_s

        elements_found = browser_obj[:browser].elements.select do |element|
          element.text == text
        end

        elements_found.each do |element_found|
          @@logger.info("#{element_found.html}\n\n\n")
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.type_as_human(
      #   string: 'required - string to type as human',
      #   rand_sleep_float: 'optional - float timing in between keypress (defaults to 0.09)'
      # )

      public_class_method def self.type_as_human(opts = {})
        string = opts[:string].to_s

        rand_sleep_float = if opts[:rand_sleep_float]
                             opts[:rand_sleep_float].to_f
                           else
                             0.09
                           end

        string.each_char do |char|
          yield char
          sleep Random.rand(rand_sleep_float)
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.close(
      #   browser_obj: 'required - browser_obj returned from #open method)'
      # )

      public_class_method def self.close(opts = {})
        browser_obj = opts[:browser_obj]

        return nil unless browser_obj.is_a?(Hash)

        browser = browser_obj[:browser]
        tor_obj = browser_obj[:tor_obj]

        PWN::Plugins::Tor.stop(tor_obj: browser_obj[:tor_obj]) if tor_obj

        # Close the browser unless browser.nil? (thus the &)
        browser&.close unless browser.to_s == 'RestClient'

        nil
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
          browser_obj1 = #{self}.open(
            browser_type: :firefox|:chrome|:headless_chrome|:headless_firefox|:rest|:websocket,
            proxy: 'optional scheme://proxy_host:port || tor',
            with_devtools: 'optional - boolean (defaults to false)'
          )
          puts browser_obj1.public_methods

          ********************************************************
          * DevTools Interaction Only works w/ Chrome
          * All DevTools Commands can be found here:
          * https://chromedevtools.github.io/devtools-protocol/
          * Examples
          devtools = browser_obj1.driver.devtools
          puts devtools.public_methods
          puts devtools.instance_variables
          puts devtools.instance_variable_get('@messages')

          * Tracing
          devtools.send_cmd('Tracing.start')
          devtools.send_cmd('Tracing.requestMemoryDump')
          devtools.send_cmd('Tracing.end')
          puts devtools.instance_variable_get('@messages')

          * Network
          devtools.send_cmd('Network.enable')
          last_ws_resp = devtools.instance_variable_get('@messages').last if devtools.instance_variable_get('@messages').last['method'] == 'Network.webSocketFrameReceived'
          puts last_ws_resp
          devtools.send_cmd('Network.disable')

          * Debugging DOM and Sending JavaScript to Console
          devtools.send_cmd('Runtime.enable')
          devtools.send_cmd('Console.enable')
          devtools.send_cmd('DOM.enable')
          devtools.send_cmd('Page.enable')
          devtools.send_cmd('Log.enable')
          devtools.send_cmd('Debugger.enable')
          devtools.send_cmd('Debugger.pause')
          step = 1
          next_step = 60
          loop do
            devtools.send_cmd('Console.clearMessages')
            devtools.send_cmd('Log.clear')
            console_events = []
            b.driver.on_log_event(:console) { |event| console_events.push(event) }

            devtools.send_cmd('Debugger.stepInto')
            puts \"Step: \#{step}\"

            this_document = devtools.send_cmd('DOM.getDocument')
            puts \"This #document:\\n\#{this_document}\\n\\n\\n\"

            console_cmd = {
              expression: 'for(var pop_var in window) { if (window.hasOwnProperty(pop_var) && window[pop_var] != null) console.log(pop_var + \" = \" + window[pop_var]); }'
            }
            puts devtools.send_cmd('Runtime.evaluate', **console_cmd)

            print '-' * 180
            print \"\\n\"
            console_events.each do |event|
              puts event.args
            end
            puts \"Console Response Length: \#{console_events.length}\"
            console_events_digest = OpenSSL::Digest::SHA256.hexdigest(
              console_events.inspect
            )
            puts \"Console Events Array SHA256 Digest: \#{console_events_digest}\"
            print '-' * 180
            puts \"\\n\\n\\n\"

            print \"Next Step in \"
            next_step.downto(1) {|n| print \"\#{n} \"; sleep 1 }
            puts 'READY!'
            step += 1
          end

          devtools.send_cmd('Debugger.disable')
          devtools.send_cmd('Log.disable')
          devtools.send_cmd('Page.disable')
          devtools.send_cmd('DOM.disable')
          devtools.send_cmd('Console.disable')
          devtools.send_cmd('Runtime.disable')
          * End of DevTools Examples
          ********************************************************

          browser_obj1 = #{self}.linkout(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          browser_obj1 = #{self}.find_element_by_text(
            browser_obj: 'required - browser_obj returned from #open method)',
            text: 'required - text to search for in the DOM'
          )

          #{self}.type_as_human(
            string: 'required - string to type as human',
            rand_sleep_float: 'optional - float timing in between keypress (defaults to 0.09)'
          ) {|char| browser_obj1.text_field(name: \"search\").send_keys(char) }

          browser_obj1 = #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          #{self}.authors
        "
      end
    end
  end
end
