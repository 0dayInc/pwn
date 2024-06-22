# frozen_string_literal: true

require 'em/pure_ruby'
require 'faye/websocket'
require 'openssl'
require 'rest-client'
require 'securerandom'
require 'selenium/webdriver'
require 'selenium/devtools'
require 'socksify'
require 'timeout'
require 'watir'

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
      # verify_devtools_browser(
      #   browser_obj: 'required - browser_obj returned from #open method',
      #   supported: 'optional - array of supported browser types (defaults to [:chrome, :headless_chrome, :firefox, :headless_firefox, :headless])'
      # )
      private_class_method def self.verify_devtools_browser(opts = {})
        browser_obj = opts[:browser_obj]
        supported = opts[:supported] ||= %i[chrome headless_chrome firefox headless_firefox headless]

        browser_type = browser_obj[:type]
        raise "ERROR: browser_type must be #{supported}" unless supported.include?(browser_type)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.open(
      #   browser_type: 'optional - :firefox|:chrome|:headless|:rest|:websocket (defaults to :chrome)',
      #   proxy: 'optional - scheme://proxy_host:port || tor (defaults to nil)',
      #   with_devtools: 'optional - boolean (defaults to true)'
      # )

      public_class_method def self.open(opts = {})
        browser_type = opts[:browser_type] ||= :chrome
        proxy = opts[:proxy].to_s unless opts[:proxy].nil?

        browser_obj = {}
        browser_obj[:type] = browser_type

        tor_obj = nil
        if opts[:proxy] == 'tor'
          tor_obj = PWN::Plugins::Tor.start
          proxy = "socks5://#{tor_obj[:ip]}:#{tor_obj[:port]}"
          browser_obj[:tor_obj] = tor_obj
        end

        with_devtools = opts[:with_devtools] ||= true

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

          options.web_socket_url = true
          options.profile = this_profile
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

          options.web_socket_url = true
          options.profile = this_profile
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

          options.web_socket_url = true
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

          options.web_socket_url = true
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

        browser_type = browser_obj[:type]
        supported = %i[chrome headless_chrome firefox headless_firefox headless]
        if with_devtools && supported.include?(browser_type)
          browser_obj[:browser].goto('about:blank')
          rand_tab = SecureRandom.hex(8)
          browser_obj[:browser].execute_script("document.title = '#{rand_tab}'")

          browser_obj[:devtools] = browser_obj[:browser].driver.devtools
          browser_obj[:bidi] = browser_obj[:browser].driver.bidi

          # browser_obj[:devtools].send_cmd('DOM.enable')
          # browser_obj[:devtools].send_cmd('Log.enable')
          # browser_obj[:devtools].send_cmd('Network.enable')
          # browser_obj[:devtools].send_cmd('Page.enable')
          # browser_obj[:devtools].send_cmd('Runtime.enable')
          # browser_obj[:devtools].send_cmd('Security.enable')

          # if browser_type == :chrome || browser_type == :headless_chrome
          #   browser_obj[:devtools].send_cmd('Debugger.enable')
          #   browser_obj[:devtools].send_cmd('DOMStorage.enable')
          #   browser_obj[:devtools].send_cmd('DOMSnapshot.enable')
          # end
        end

        browser_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::Plugins::TransparentBrowser.dump_links(
      #   browser_obj: browser_obj1
      # )

      public_class_method def self.dump_links(opts = {})
        browser_obj = opts[:browser_obj]

        links = browser_obj[:browser].links

        dump_links_arr = []
        links.each do |link|
          link_hash = {}

          link_hash[:text] = link.text
          link_hash[:href] = link.href
          link_hash[:id] = link.id
          link_hash[:name] = link.name
          link_hash[:class_name] = link.class_name
          link_hash[:html] = link.html
          link_hash[:target] = link.target
          dump_links_arr.push(link_hash)

          yield link if block_given?
        end

        dump_links_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::Plugins::TransparentBrowser.find_elements_by_text(
      #   browser_obj: browser_obj1,
      #   text: 'required - text to search for in the DOM'
      # )

      public_class_method def self.find_elements_by_text(opts = {})
        browser_obj = opts[:browser_obj]
        text = opts[:text].to_s

        elements = browser_obj[:browser].elements
        elements_found_arr = []
        elements.each do |element|
          begin
            if element.text == text || element.value == text
              element_hash = {}
              element_hash[:tag_name] = element.tag_name
              element_hash[:html] = element.html
              elements_found_arr.push(element_hash)

              yield element if block_given?
            end
          rescue NoMethodError
            next
          end
        end

        elements_found_arr
      rescue StandardError => e
        puts e.backtrace
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
      # console_resp = PWN::Plugins::TransparentBrowser.console(
      #   browser_obj: browser_obj1,
      #   js: 'required - JavaScript expression to evaluate'
      # )

      public_class_method def self.console(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        js = opts[:js] ||= "alert('ACK from => #{self}')"

        browser = browser_obj[:browser]
        case js
        when 'debugger', 'debugger;', 'debugger()', 'debugger();'
          Timeout.timeout(1) { console_resp = browser.execute_script('debugger') }
        when 'clear', 'clear;', 'clear()', 'clear();'
          console_resp = browser.execute_script('console.clear()')
        else
          console_resp = browser.execute_script("console.log(#{js})")
        end

        console_resp
      rescue Timeout::Error, Timeout::ExitException
        console_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # tabs = PWN::Plugins::TransparentBrowser.list_tabs(
      #   browser_obj: 'required - browser_obj returned from #open method)'
      # )

      public_class_method def self.list_tabs(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        browser = browser_obj[:browser]
        browser.windows.map do |tab|
          active = false
          active = true if browser.title == tab.title && browser.url == tab.url
          { title: tab.title, url: tab.url, active: active }
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.switch_tab(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   keyword: 'required - keyword in title or url used to switch tabs'
      # )

      public_class_method def self.switch_tab(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        keyword = opts[:keyword]
        raise 'ERROR: keyword parameter is required' if keyword.nil?

        browser = browser_obj[:browser]
        all_tabs = browser.windows
        all_tabs.select { |tab| tab.use if tab.title.include?(keyword) || tab.url.include?(keyword) }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.new_tab(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   url: 'optional - URL to navigate to after opening new tab (Defaults to nil)'
      # )

      public_class_method def self.new_tab(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        url = opts[:url]

        browser = browser_obj[:browser]
        browser.execute_script('window.open()')
        switch_tab(browser_obj: browser_obj, keyword: 'about:blank')
        rand_tab = SecureRandom.hex(8)
        browser.execute_script("document.title = '#{rand_tab}'")
        browser.goto(url) unless url.nil?

        { title: browser.title, url: browser.url, active: active }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.close_tab(
      #   browser_obj: 'required - browser_obj returned from #open method)'
      #   keyword: 'required - keyword in title or url used to close tabs'
      # )

      public_class_method def self.close_tab(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        keyword = opts[:keyword]
        raise 'ERROR: keyword parameter is required' if keyword.nil?

        browser = browser_obj[:browser]
        all_tabs = browser.windows
        all_tabs.select { |tab| tab.close if tab.title.include?(keyword) || tab.url.include?(keyword) }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.debugger(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   action: 'optional - action to take :pause|:resume (Defaults to :pause)',
      #   url: 'optional - URL to navigate to after pausing debugger (Defaults to nil)'
      # )

      public_class_method def self.debugger(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)
        browser = browser_obj[:browser]
        action = opts[:action] ||= :pause
        url = opts[:url]

        devtools = browser_obj[:devtools]

        case action.to_s.downcase.to_sym
        when :pause
          console(browser_obj: browser_obj, js: 'debugger')

          # devtools.send_cmd('Debugger.enable')
          # devtools.send_cmd(
          #   'Debugger.setInstrumentationBreakpoint',
          #   instrumentation: 'beforeScriptExecution'
          # )

          # devtools.send_cmd(
          #   'EventBreakpoints.setInstrumentationBreakpoint',
          #   eventName: 'load'
          # )

          # devtools.send_cmd(
          #   'Debugger.setPauseOnExceptions',
          #   state: 'all'
          # )

          begin
            Timeout.timeout(1) do
              browser.refresh if url.nil?
              browser.goto(url) unless url.nil?
            end
          rescue Timeout::Error
            url
          end
        when :resume
          devtools.send_cmd('Debugger.resume')
        else
          raise 'ERROR: action parameter must be :pause or :resume'
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.step_into(
      #   browser_obj: 'required - browser_obj returned from #open method)'
      # )

      public_class_method def self.step_into(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)

        devtools = browser_obj[:devtools]
        devtools.send_cmd('Debugger.stepInto')
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.step_out(
      #   browser_obj: 'required - browser_obj returned from #open method)'
      # )

      public_class_method def self.step_out(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)

        devtools = browser_obj[:devtools]
        devtools.send_cmd('Debugger.stepOut')
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # browser_obj1 = PWN::Plugins::TransparentBrowser.step_over(
      #   browser_obj: 'required - browser_obj returned from #open method)'
      # )

      public_class_method def self.step_over(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)

        devtools = browser_obj[:devtools]
        devtools.send_cmd('Debugger.stepOver')
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
            browser_type: 'optional - :firefox|:chrome|:headless|:rest|:websocket (defaults to :chrome)',
            proxy: 'optional scheme://proxy_host:port || tor (defaults to nil)',
            with_devtools: 'optional - boolean (defaults to true)'
          )
          browser = browser_obj1[:browser]
          puts browser.public_methods

          ********************************************************
          * DevTools Interaction
          * All DevTools Commands can be found here:
          * https://chromedevtools.github.io/devtools-protocol/
          * Examples
          devtools = browser.driver.devtools
          puts devtools.public_methods
          puts devtools.instance_variables
          puts devtools.instance_variable_get('@session_id')

          websocket = devtools.instance_variable_get('@ws')
          puts websocket.public_methods
          puts websocket.instance_variables
          puts websocket.instance_variable_get('@messages')

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
            browser.driver.on_log_event(:console) { |event| console_events.push(event) }

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

          browser_obj1 = #{self}.dump_links(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          browser_obj1 = #{self}.find_elements_by_text(
            browser_obj: 'required - browser_obj returned from #open method)',
            text: 'required - text to search for in the DOM'
          )

          #{self}.type_as_human(
            string: 'required - string to type as human',
            rand_sleep_float: 'optional - float timing in between keypress (defaults to 0.09)'
          ) {|char| browser_obj1.text_field(name: \"search\").send_keys(char) }

          console_resp = #{self}.console(
            browser_obj: 'required - browser_obj returned from #open method)',
            js: 'required - JavaScript expression to evaluate'
          )

          tabs = #{self}.list_tabs(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          browser_obj1 = #{self}.switch_tab(
            browser_obj: 'required - browser_obj returned from #open method)',
            keyword: 'required - keyword in title or url used to switch tabs'
          )

          browser_obj1 = #{self}.new_tab(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          browser_obj1 = #{self}.close_tab(
            browser_obj: 'required - browser_obj returned from #open method)',
            keyword: 'required - keyword in title or url used to close tabs'
          )

          browser_obj1 = #{self}.debugger(
            browser_obj: 'required - browser_obj returned from #open method)',
            action: 'optional - action to take :pause|:resume (Defaults to :pause)',
            url: 'optional - URL to navigate to after pausing debugger (Defaults to nil)'
          )

          browser_obj1 = #{self}.step_into(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          browser_obj1 = #{self}.step_out(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          browser_obj1 = #{self}.step_over(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          browser_obj1 = #{self}.close(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          #{self}.authors
        "
      end
    end
  end
end
