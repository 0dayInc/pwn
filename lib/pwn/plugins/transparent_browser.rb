# frozen_string_literal: true

require 'watir'
require 'selenium/webdriver'
require 'selenium/devtools'
require 'rest-client'
require 'socksify'
require 'em/pure_ruby'
require 'faye/websocket'

module PWN
  module Plugins
    # This plugin rocks. Chrome, Firefox, PhantomJS, IE, REST Client,
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
      #   proxy: 'optional - scheme://proxy_host:port',
      #   with_tor: 'optional - boolean (defaults to false)'
      #   with_devtools: 'optional - boolean (defaults to false)'
      # )

      public_class_method def self.open(opts = {})
        this_browser = nil
        browser_type = opts[:browser_type]
        proxy = opts[:proxy].to_s unless opts[:proxy].nil?
        opts[:with_tor] ? (with_tor = true) : (with_tor = false)
        opts[:with_devtools] ? (with_devtools = true) : (with_devtools = false)

        # Let's crank up the default timeout from 30 seconds to 15 min for slow sites
        Watir.default_timeout = 900

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
            if with_tor
              this_profile['network.proxy.socks_version'] = 5
              this_profile['network.proxy.socks'] = URI(proxy).host
              this_profile['network.proxy.socks_port'] = URI(proxy).port
            else
              this_profile['network.proxy.ftp'] = URI(proxy).host
              this_profile['network.proxy.ftp_port'] = URI(proxy).port
              this_profile['network.proxy.http'] = URI(proxy).host
              this_profile['network.proxy.http_port'] = URI(proxy).port
              this_profile['network.proxy.ssl'] = URI(proxy).host
              this_profile['network.proxy.ssl_port'] = URI(proxy).port
            end
          end

          args = []

          args.push('--devtools') if with_devtools
          options = Selenium::WebDriver::Firefox::Options.new(args: args, accept_insecure_certs: true)
          options.profile = this_profile
          driver = Selenium::WebDriver.for(:firefox, capabilities: options)
          this_browser = Watir::Browser.new(driver)

        when :chrome
          this_profile = Selenium::WebDriver::Chrome::Profile.new
          this_profile['download.prompt_for_download'] = false
          this_profile['download.default_directory'] = '~/Downloads'

          switches = []
          if proxy
            switches.push("--host-resolver-rules='MAP * 0.0.0.0 , EXCLUDE #{URI(proxy).host}'") if with_tor
            switches.push("--proxy-server=#{proxy}")
          end

          if with_devtools
            switches.push('--auto-open-devtools-for-tabs')
            switches.push('--disable-hang-monitor')
          end

          options = Selenium::WebDriver::Chrome::Options.new(
            args: switches,
            accept_insecure_certs: true
          )

          options.profile = this_profile
          driver = Selenium::WebDriver.for(:chrome, capabilities: options)
          this_browser = Watir::Browser.new(driver)

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
            if with_tor
              this_profile['network.proxy.socks_version'] = 5
              this_profile['network.proxy.socks'] = URI(proxy).host
              this_profile['network.proxy.socks_port'] = URI(proxy).port
            else
              this_profile['network.proxy.ftp'] = URI(proxy).host
              this_profile['network.proxy.ftp_port'] = URI(proxy).port
              this_profile['network.proxy.http'] = URI(proxy).host
              this_profile['network.proxy.http_port'] = URI(proxy).port
              this_profile['network.proxy.ssl'] = URI(proxy).host
              this_profile['network.proxy.ssl_port'] = URI(proxy).port
            end
          end

          options = Selenium::WebDriver::Firefox::Options.new(args: ['-headless'], accept_insecure_certs: true)
          options.profile = this_profile
          driver = Selenium::WebDriver.for(:firefox, capabilities: options)
          this_browser = Watir::Browser.new(driver)

        when :headless_chrome
          this_profile = Selenium::WebDriver::Chrome::Profile.new
          this_profile['download.prompt_for_download'] = false
          this_profile['download.default_directory'] = '~/Downloads'

          switches = []
          switches.push('-headless')
          if proxy
            switches.push("--host-resolver-rules='MAP * 0.0.0.0 , EXCLUDE #{URI(proxy).host}'") if with_tor
            switches.push("--proxy-server=#{proxy}")
          end

          options = Selenium::WebDriver::Chrome::Options.new(
            args: switches,
            accept_insecure_certs: true
          )

          options.profile = this_profile
          driver = Selenium::WebDriver.for(:chrome, capabilities: options)
          this_browser = Watir::Browser.new(driver)

        when :rest
          this_browser = RestClient
          if proxy
            if with_tor
              TCPSocket.socks_server = URI(proxy).host
              TCPSocket.socks_port = URI(proxy).port
            else
              this_browser.proxy = proxy
            end
          end

        when :websocket
          if proxy
            if with_tor
              TCPSocket.socks_server = URI(proxy).host
              TCPSocket.socks_port = URI(proxy).port
            end
            proxy_opts = { origin: proxy }
            tls_opts = { verify_peer: false }
            this_browser = Faye::WebSocket::Client.new(
              '',
              [],
              {
                tls: tls_opts,
                proxy: proxy_opts
              }
            )
          else
            this_browser = Faye::WebSocket::Client.new('')
          end
        else
          puts 'Error: browser_type only supports :firefox, :chrome, :headless, :rest, or :websocket'
          return nil
        end

        this_browser
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::Plugins::TransparentBrowser.linkout(
      #   browser_obj: browser_obj1
      # )

      public_class_method def self.linkout(opts = {})
        this_browser_obj = opts[:browser_obj]

        this_browser_obj.links.each do |link|
          @@logger.info("#{link.text} => #{link.href}\n\n\n") unless link.text == ''
        end

        this_browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.type_as_human(
      #   q: 'required - query string to randomize',
      #   rand_sleep_float: 'optional - float timing in between keypress (defaults to 0.09)'
      # )

      public_class_method def self.type_as_human(opts = {})
        query_string = opts[:q].to_s

        rand_sleep_float = if opts[:rand_sleep_float]
                             opts[:rand_sleep_float].to_f
                           else
                             0.09
                           end

        query_string.each_char do |char|
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
        this_browser_obj = opts[:browser_obj]

        unless this_browser_obj.to_s.include?('RestClient')
          # Close the browser unless this_browser_obj.nil? (thus the &)
          this_browser_obj&.close
        end
        nil
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
          browser_obj1 = #{self}.open(
            browser_type: :firefox|:chrome|:headless_chrome|:headless_firefox|:rest|:websocket,
            proxy: 'optional scheme://proxy_host:port',
            with_tor: 'optional boolean (defaults to false)',
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
          devtools.send_cmd('DOM.enable')
          devtools.send_cmd('Log.enable')
          devtools.send_cmd('Debugger.enable')
          devtools.send_cmd('Debugger.pause')
          console_cmd = {
            expression: 'console.log(global);'
          }
          step = 1
          loop do
            devtools.send_cmd('Debugger.stepInto')
            puts \"Step: \#{step}\"
            this_call = devtools.instance_variable_get('@messages').last['params']['callFrames'].last if devtools.instance_variable_get('@messages').last['method'] == 'Debugger.paused'
            puts \"Function Name: \#{this_call['functionName']}\"
            this_document = devtools.send_cmd('DOM.getDocument')
            puts \"This #document:\\n\#{this_document}\\n\\n\\n\"

            this_global = devtools.send_cmd(
              'Runtime.evaluate',
              **console_cmd
            )
            puts \"This #global:\\n\#{this_global}\\n\\n\\n\"

            sleep 9
          end
          devtools.send_cmd('Debugger.disable')
          devtools.send_cmd('DOM.disable')
          devtools.send_cmd('Runtime.disable')
          * End of DevTools Examples
          ********************************************************

          browser_obj1 = #{self}.linkout(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          #{self}.type_as_human(
            q: 'required - query string to randomize',
            rand_sleep_float: 'optional - float timing in between keypress (defaults to 0.09)'
          ) {|char| browser_obj1.text_field(name: \"q\").send_keys(char) }

          browser_obj1 = #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          #{self}.authors
        "
      end
    end
  end
end
