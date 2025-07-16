# frozen_string_literal: true

require 'em/pure_ruby'
require 'faye/websocket'
# require 'openapi3_parser'
require 'openssl'
require 'rest-client'
require 'securerandom'
require 'selenium/webdriver'
require 'selenium/devtools'
require 'socksify'
require 'timeout'
require 'watir'
require 'yaml'

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
      #   devtools: 'optional - boolean (defaults to false)',
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

        devtools_supported = %i[chrome headless_chrome firefox headless_firefox headless]
        devtools = opts[:devtools] ||= false
        devtools = true if devtools_supported.include?(browser_type) && devtools

        # Let's crank up the default timeout from 30 seconds to 15 min for slow sites
        Watir.default_timeout = 900

        args = []
        # args.push('--start-maximized')
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

          if devtools
            # args.push('--start-debugger-server')
            # this_profile['devtools.debugger.remote-enabled'] = true
            # this_profile['devtools.debugger.remote-host'] = 'localhost'
            # this_profile['devtools.debugger.remote-port'] = 6000

            # DevTools ToolBox Settings in Firefox about:config
            this_profile['devtools.f12.enabled'] = true
            this_profile['devtools.toolbox.host'] = 'right'
            this_profile['devtools.toolbox.selectedTool'] = 'jsdebugger'
            this_profile['devtools.toolbox.sidebar.width'] = 1700
            this_profile['devtools.toolbox.splitconsoleHeight'] = 200

            # DevTools Debugger Settings in Firefox about:config
            this_profile['devtools.chrome.enabled'] = true
            this_profile['devtools.debugger.start-panel-size'] = 200
            this_profile['devtools.debugger.end-panel-size'] = 200
            this_profile['devtools.debugger.auto-pretty-print'] = true
            this_profile['devtools.debugger.ui.editor-wrapping'] = true
            this_profile['devtools.debugger.features.javascript-tracing'] = true
            this_profile['devtools.debugger.xhr-breakpoints-visible'] = true
            this_profile['devtools.debugger.expressions-visible'] = true
            this_profile['devtools.debugger.dom-mutation-breakpoints-visible'] = true
            this_profile['devtools.debugger.features.async-live-stacks'] = true
            this_profile['devtools.debugger.features.autocomplete-expressions'] = true
            this_profile['devtools.debugger.features.code-folding'] = true
            this_profile['devtools.debugger.features.command-click'] = true
            this_profile['devtools.debugger.features.component-pane'] = true
            this_profile['devtools.debugger.map-scopes-enabled'] = true

            # Never optimize out variables in the debugger
            this_profile['javascript.options.baselinejit'] = false
            this_profile['javascript.options.ion'] = false
          end

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

          # Private browsing mode
          args.push('--private')
          options = Selenium::WebDriver::Firefox::Options.new(
            args: args,
            accept_insecure_certs: true
          )

          # This is required for BiDi support
          options.web_socket_url = true
          options.add_preference('remote.active-protocols', 3)
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

          if devtools
            args.push('--auto-open-devtools-for-tabs')
            args.push('--disable-hang-monitor')
          end

          # Incognito browsing mode
          args.push('--incognito')
          options = Selenium::WebDriver::Chrome::Options.new(
            args: args,
            accept_insecure_certs: true
          )

          # This is required for BiDi support
          options.web_socket_url = true
          options.add_preference('remote.active-protocols', 3)
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
          # Private browsing mode
          args.push('--private')
          options = Selenium::WebDriver::Firefox::Options.new(
            args: args,
            accept_insecure_certs: true
          )

          # This is required for BiDi support
          options.web_socket_url = true
          options.add_preference('remote.active-protocols', 3)
          options.profile = this_profile
          driver = Selenium::WebDriver.for(:firefox, options: options)
          browser_obj[:browser] = Watir::Browser.new(driver)

        when :headless_chrome
          this_profile = Selenium::WebDriver::Chrome::Profile.new
          this_profile['download.prompt_for_download'] = false
          this_profile['download.default_directory'] = '~/Downloads'

          if proxy
            args.push("--host-resolver-rules='MAP * 0.0.0.0 , EXCLUDE #{tor_obj[:ip]}'") if tor_obj
            args.push("--proxy-server=#{proxy}")
          end

          args.push('--headless')
          # Incognito browsing mode
          args.push('--incognito')
          options = Selenium::WebDriver::Chrome::Options.new(
            args: args,
            accept_insecure_certs: true
          )

          # This is required for BiDi support
          options.web_socket_url = true
          options.add_preference('remote.active-protocols', 3)
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
          puts 'Error: browser_type only supports :firefox, :chrome, :headless, :headless_chrome, :headless_firefox, :rest, :websocket'
          return nil
        end

        if devtools && devtools_supported.include?(browser_type)
          chrome_types = %i[chrome headless_chrome]
          firefox_types = %i[firefox headless_firefox]

          # Future BiDi API that's more universally supported across browsers
          sleep 0.01 until browser_obj[:browser].driver.window_handles.any?
          target_window_handle = browser_obj[:browser].driver.window_handles.last
          browser_obj[:browser].driver.switch_to.window(target_window_handle)

          url = 'about:about'
          url = 'chrome://chrome-urls/' if chrome_types.include?(browser_type)
          browser_obj[:browser].goto(url)
          rand_tab = SecureRandom.hex(8)
          browser_obj[:browser].execute_script("document.title = 'about:about-#{rand_tab}'")

          browser_obj[:browser].driver.manage.window.maximize
          toggle_devtools(browser_obj: browser_obj)

          browser_obj[:bidi] = browser_obj[:browser].driver.bidi
          browser_obj[:devtools] = browser_obj[:browser].driver.devtools if chrome_types.include?(browser_type)
          browser_obj[:devtools] = browser_obj[:browser].driver.bidi if firefox_types.include?(browser_type)
        end

        browser_obj
      rescue StandardError => e
        puts e.backtrace
        raise e
      end

      # Supported Method Parameters::
      # browser_obj = PWN::Plugins::TransparentBrowser.dump_links(
      #   browser_obj: browser_obj1
      # )

      public_class_method def self.dump_links(opts = {})
        browser_obj = opts[:browser_obj]

        dump_links_arr = []
        browser_obj[:browser].links.each do |link|
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
      #   js: 'required - JavaScript expression to evaluate',
      #   return_to: 'optional - return to :console or :stdout (defaults to :console)'
      # )

      public_class_method def self.console(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        js = opts[:js] ||= "alert('ACK from => #{self}')"
        return_to = opts[:return_to] ||= :console
        raise 'ERROR: return_to parameter must be :console or :stdout' unless %i[console stdout].include?(return_to.to_s.downcase.to_sym)

        case js
        when 'clear', 'clear;', 'clear()', 'clear();'
          script = 'console.clear()'
        else
          case return_to.to_s.downcase.to_sym
          when :stdout
            script = "return #{js}"
          when :console
            script = "console.log(#{js})"
          end
        end

        console_resp = nil
        begin
          Timeout.timeout(1) { console_resp = browser_obj[:browser].execute_script(script) }
        rescue Timeout::Error, Timeout::ExitException
          console_resp
        rescue Selenium::WebDriver::Error::JavascriptError
          script = js
          retry
        end

        console_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # console_resp = PWN::Plugins::TransparentBrowser.view_dom_mutations(
      #   browser_obj: browser_obj1,
      #   index: 'optional - index of tab to switch to (defaults to active tab)',
      #   target: 'optional - target JavaScript node to observe (defaults to document.body)'
      # )

      public_class_method def self.view_dom_mutations(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        index = opts[:index]
        jmp_tab(browser_obj: browser_obj, index: index) if index

        target = opts[:target] ||= 'undefined'

        jmp_devtools_panel(
          browser_obj: browser_obj,
          panel: :console
        )

        js = <<~JAVASCRIPT
          // Select the target node to observe (replace 'target-id' with your element's ID or use document.body)
          const targetNode = document.getElementById(#{target}) || document.body;

          // Configuration for MutationObserver
          const config = {
            attributes: true, // Observe attribute changes
            childList: true, // Observe additions/removals of child nodes
            subtree: true, // Observe descendants
            characterData: true, // Observe text content changes
          };

          // Callback function to handle mutations
          const callback = (mutationList, observer) => {
            console.group('DOM Mutation Detected');
            mutationList.forEach((mutation, index) => {
              console.log(`Mutation ${index + 1}:`, mutation.type);

              if (mutation.type === 'childList') {
                if (mutation.addedNodes.length) {
                  mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                      let logObj = {
                        tagName: node.tagName,
                        id: node.id || 'N/A',
                        classList: node.className || 'N/A',
                        outerHTML: node.outerHTML,
                      };
                      if (['SCRIPT', 'IFRAME', 'FRAME', 'OBJECT', 'EMBED', 'APPLET'].includes(node.tagName)) {
                        console.warn('Potential XSS sink: Added', node.tagName, logObj);
                      } else {
                        console.log('Added Element:', logObj);
                      }
                    } else if (node.nodeType === Node.TEXT_NODE) {
                      console.log('Added Text Node:', {
                        textContent: node.textContent,
                        parentTag: node.parentElement?.tagName || 'N/A',
                      });
                    }
                  });
                }
                if (mutation.removedNodes.length) {
                  mutation.removedNodes.forEach((node) => {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                      console.log('Removed Element:', {
                        tagName: node.tagName,
                        id: node.id || 'N/A',
                        classList: node.className || 'N/A',
                        outerHTML: node.outerHTML,
                      });
                    } else if (node.nodeType === Node.TEXT_NODE) {
                      console.log('Removed Text Node:', {
                        textContent: node.textContent,
                        parentTag: node.parentElement?.tagName || 'N/A',
                      });
                    }
                  });
                }
              } else if (mutation.type === 'attributes') {
                let logObj = {
                  element: mutation.target.tagName,
                  id: mutation.target.id || 'N/A',
                  attribute: mutation.attributeName,
                  oldValue: mutation.oldValue,
                  newValue: mutation.target.getAttribute(mutation.attributeName),
                  outerHTML: mutation.target.outerHTML,
                };
                if (
                  (mutation.attributeName === 'src' && ['SCRIPT', 'IFRAME', 'FRAME', 'OBJECT', 'EMBED'].includes(mutation.target.tagName)) ||
                  (mutation.attributeName === 'href' && ['A', 'AREA', 'LINK'].includes(mutation.target.tagName)) ||
                  (mutation.attributeName === 'action' && mutation.target.tagName === 'FORM') ||
                  mutation.attributeName.startsWith('on') ||
                  (mutation.attributeName === 'srcdoc' && mutation.target.tagName === 'IFRAME') ||
                  (mutation.attributeName === 'data' && mutation.target.tagName === 'OBJECT') ||
                  (mutation.attributeName === 'codebase' && mutation.target.tagName === 'OBJECT')
                ) {
                  console.warn('Potential XSS sink: Attribute change', logObj);
                } else {
                  console.log('Attribute changed:', logObj);
                }
              } else if (mutation.type === 'characterData') {
                if (mutation.target.parentElement && mutation.target.parentElement.tagName === 'SCRIPT') {
                  console.warn('Potential XSS sink: Script content changed', {
                    scriptId: mutation.target.parentElement.id || 'N/A',
                    oldValue: mutation.oldValue,
                    newValue: mutation.target.textContent,
                  });
                } else {
                  console.log('Text Content Changed:', {
                    element: mutation.target.parentElement?.tagName || 'N/A',
                    id: mutation.target.parentElement?.id || 'N/A',
                    oldValue: mutation.oldValue,
                    newValue: mutation.target.textContent,
                    innerHTML: mutation.target.parentElement?.innerHTML || 'N/A',
                  });
                }
              }
            });
            console.groupEnd();
          };

          // Create and start the MutationObserver
          const observer = new MutationObserver(callback);
          observer.observe(targetNode, config);

          // Optional: Add event listeners to capture user interactions
          const logUserInteraction = (event) => {
            console.group('User Interaction Detected');
            console.log('Event Type:', event.type);
            console.log('Target:', {
              tagName: event.target.tagName,
              id: event.target.id || 'N/A',
              classList: event.target.className || 'N/A',
              value: 'value' in event.target ? event.target.value : 'N/A',
              innerHTML: event.target.innerHTML || 'N/A',
            });
            console.groupEnd();
          };

          // Attach listeners for keyboard and click events
          document.addEventListener('input', logUserInteraction); // For form inputs, contenteditable
          document.addEventListener('click', logUserInteraction); // For clicks

          // Function to stop the observer (run in console when needed)
          window.hide_dom_mutations = () => {
            observer.disconnect();
            document.removeEventListener('input', logUserInteraction);
            document.removeEventListener('click', logUserInteraction);
            console.log('MutationObserver and event listeners stopped.');
          };

          // Log instructions to console
          console.log('MutationObserver started. To stop, run: hide_dom_mutations()');
        JAVASCRIPT

        console(browser_obj: browser_obj, js: 'clear();')
        browser_obj[:browser].execute_script(js)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # console_resp = PWN::Plugins::TransparentBrowser.hide_dom_mutations(
      #   browser_obj: browser_obj1,
      #   index: 'optional - index of tab to switch to (defaults to active tab)'
      # )

      public_class_method def self.hide_dom_mutations(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        index = opts[:index]
        jmp_tab(browser_obj: browser_obj, index: index) if index

        jmp_devtools_panel(
          browser_obj: browser_obj,
          panel: :console
        )

        js = <<~JAVASCRIPT
          if (typeof hide_dom_mutations === 'function') {
            hide_dom_mutations();
            console.log('DOM mutation observer and event listeners disabled.');
          } else {
            console.log('Error: hide_dom_mutations function not found. DOM mutation observer was not active.');
          }
        JAVASCRIPT

        console(browser_obj: browser_obj, js: 'clear();')
        browser_obj[:browser].execute_script(js)
      rescue StandardError => e
        raise e
      end
      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.update_about_config(
      #   browser_obj: browser_obj1,
      #   key: 'required - key to update in about:config',
      #   value: 'required - value to set for key in about:config'
      # )

      public_class_method def self.update_about_config(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[firefox headless_firefox]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)

        key = opts[:key]
        raise 'ERROR: key parameter is required' if key.nil?

        value = opts[:value]
        raise 'ERROR: value parameter is required' if value.nil?

        browser_type = browser_obj[:type]
        # chrome_types = %i[chrome headless_chrome]
        firefox_types = %i[firefox headless_firefox]

        browser_obj[:browser].goto('about:config')
        # Confirmed working in Firefox
        js = %{Services.prefs.setStringPref("#{key}", "#{value}")} if firefox_types.include?(browser_type)
        console(browser_obj: browser_obj, js: js)
        browser_obj[:browser].back
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

        idx = 0
        current_window_handle = browser_obj[:browser].driver.window_handle

        tabs_arr_hash = browser_obj[:browser].windows.map do |tab|
          next if tab.url.include?('devtools://')

          state = :inactive
          window_handle = browser_obj[:browser].driver.window_handles[idx]
          state = :active if window_handle == current_window_handle

          idx += 1

          { index: window_handle, title: tab.title, url: tab.url, state: state }
        end.compact

        # Ensure we have a visible tab that's active
        active_tab = tabs_arr_hash.find { |tab| tab[:state] == :active } || tabs_arr_hash.first
        # Ensure we're back to the active tab
        browser_obj[:browser].driver.switch_to.window(active_tab[:index])

        tabs_arr_hash
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # tab = PWN::Plugins::TransparentBrowser.jmp_tab(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   index: 'optional - index of tab to switch to (defaults to switching to next tab)',
      #   keyword: 'optional - keyword in title or url used to switch tabs (defaults to switching to next tab)'
      # )

      public_class_method def self.jmp_tab(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        index = opts[:index]
        keyword = opts[:keyword]

        tabs_arr_hash = list_tabs(browser_obj: browser_obj)

        if index.nil? && keyword.nil?
          # If no keyword is provided, switch to the next tab in the list
          active_tab_index = tabs_arr_hash.find_index { |tab| tab[:state] == :active }
          next_tab_index = (active_tab_index + 1) % tabs_arr_hash.size
          # Find value of :index key from tabs_arr_hash
          tab_sel = tabs_arr_hash[next_tab_index]
        elsif index
          tab_sel = tabs_arr_hash.find { |tab| tab[:index] == index }
        else
          tab_sel = tabs_arr_hash.find { |tab| tab[:title].include?(keyword) || tab[:url].include?(keyword) }
        end

        if tab_sel.is_a?(Hash) && tab_sel[:index]
          index = tab_sel[:index]
          browser_obj[:browser].driver.switch_to.window(index)
        else
          tab_sel = { index: index, error: 'not found' }
        end

        tab_sel
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # tab = PWN::Plugins::TransparentBrowser.new_tab(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   url: 'optional - URL to open in new tab'
      # )

      public_class_method def self.new_tab(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        url = opts[:url]
        chrome_types = %i[chrome headless_chrome]
        firefox_types = %i[firefox headless_firefox]

        browser_type = browser_obj[:type]

        if url.nil? || url.empty?
          url = 'about:about' if firefox_types.include?(browser_type)
          url = 'chrome://chrome-urls/' if chrome_types.include?(browser_type)
        end

        # Open a new tab
        console(
          browser_obj: browser_obj,
          js: "window.open('#{url}', '_blank')",
          return_to: :stdout
        )

        # tabs_arr_hash = list_tabs(browser_obj: browser_obj)
        # new_tab_index = tabs_arr_hash.find { |tab| tab[:state] == :inactive && tab[:url] == url }[:index]
        # jmp_tab(browser_obj: browser_obj, index: new_tab_index)
        jmp_tab(browser_obj: browser_obj)
        new_tab_index = browser_obj[:browser].driver.window_handles.last

        rand_tab = SecureRandom.hex(8)
        browser_obj[:browser].execute_script("document.title = 'about:about-#{rand_tab}'")
        toggle_devtools(browser_obj: browser_obj) if browser_obj[:devtools]

        { index: new_tab_index, title: browser_obj[:browser].title, url: browser_obj[:browser].url, state: :active }
      rescue StandardError => e
        puts e.backtrace
        raise e
      end

      # Supported Method Parameters::
      # tab = PWN::Plugins::TransparentBrowser.close_tab(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   index: 'optional - index of tab to close (defaults to closing active tab)',
      #   keyword: 'optional - keyword in title or url used to close tabs (defaults to closing active tab)'
      # )

      public_class_method def self.close_tab(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        index = opts[:index]
        keyword = opts[:keyword]

        tabs_arr_hash = list_tabs(browser_obj: browser_obj)
        browser_ready_to_close = true if tabs_arr_hash.length == 1

        if browser_ready_to_close
          close(browser_obj: browser_obj)
          return [{ index: nil, title: nil, url: nil, state: :browser_closed }]
        elsif index.nil? && keyword.nil?
          index = browser_obj[:browser].driver.window_handle
          browser_obj[:browser].driver.switch_to.window(index)
          browser_obj[:browser].driver.close
          new_tab_index_arr = browser_obj[:browser].driver.window_handles
          if new_tab_index_arr.any?
            new_tab_index = new_tab_index_arr.last
            browser_obj[:browser].driver.switch_to.window(new_tab_index)
          end
        elsif index
          browser_obj[:browser].driver.switch_to.window(index)
          browser_obj[:browser].driver.close
          new_tab_index_arr = browser_obj[:browser].driver.window_handles
          if new_tab_index_arr.any?
            new_tab_index = new_tab_index_arr.last
            browser_obj[:browser].driver.switch_to.window(new_tab_index)
          end
        else
          active_tab = tabs_arr_hash.find { |tab| tab[:state] == :active }
          if active_tab[:url].include?(keyword)
            inactive_tabs = tabs_arr_hash.reject { |tab| tab[:url] == browser_obj[:browser].url }
            if inactive_tabs.any?
              tab_to_activate = inactive_tabs.last[:url]
              jmp_tab(browser_obj: browser_obj, keyword: tab_to_activate)
            end
          end
          all_tabs = browser_obj[:browser].windows

          tabs_to_close = all_tabs.select { |tab| tab.title.include?(keyword) || tab.url.include?(keyword) }
          tabs_to_close.each(&:close)
        end

        list_tabs(browser_obj: browser_obj)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.debugger(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   action: 'optional - action to take :pause|:resume (Defaults to :pause)',
      #   url: 'optional - URL to navigate to after pausing debugger (Defaults to nil)'
      # )

      public_class_method def self.debugger(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)
        action = opts[:action] ||= :pause
        url = opts[:url]

        case action.to_s.downcase.to_sym
        when :pause
          browser_obj[:devtools].send_cmd(
            'EventBreakpoints.setInstrumentationBreakpoint',
            eventName: 'scriptFirstStatement'
          )
          # browser_obj[:devtools].send_cmd('Debugger.enable')
          # browser_obj[:devtools].send_cmd(
          #   'Debugger.setInstrumentationBreakpoint',
          #   instrumentation: 'beforeScriptExecution'
          # )

          # browser_obj[:devtools].send_cmd(
          #   'EventBreakpoints.setInstrumentationBreakpoint',
          #   eventName: 'load'
          # )

          # browser_obj[:devtools].send_cmd(
          #   'Debugger.setPauseOnExceptions',
          #   state: 'all'
          # )

          begin
            Timeout.timeout(1) do
              browser_obj[:browser].refresh if url.nil?
              browser_obj[:browser].goto(url) unless url.nil?
            end
          rescue Timeout::Error
            url
          end
        when :resume
          browser_obj[:devtools].send_cmd(
            'EventBreakpoints.removeInstrumentationBreakpoint',
            eventName: 'scriptFirstStatement'
          )
          browser_obj[:devtools].send_cmd('Debugger.resume')
        else
          raise 'ERROR: action parameter must be :pause or :resume'
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # current_dom = PWN::Plugins::TransparentBrowser.dom(
      #   browser_obj: 'required - browser_obj returned from #open method)'
      # )

      public_class_method def self.dom(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)

        computed_styles = %i[display color font-size font-family]
        browser_obj[:devtools].send_cmd(
          'DOMSnapshot.captureSnapshot',
          computedStyles: computed_styles
        ).transform_keys(&:to_sym)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.step_into(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   steps: 'optional - number of steps taken (Defaults to 1)'
      # )

      public_class_method def self.step_into(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)

        steps = opts[:steps].to_i
        steps = 1 if steps.zero? || steps.negative?

        diff_arr = []
        steps.times do |s|
          diff_hash = {}
          step = s + 1
          diff_hash[:step] = step

          dom_before = dom(browser_obj: browser_obj)
          diff_hash[:dom_before_step] = dom_before

          browser_obj[:devtools].send_cmd('Debugger.stepInto')

          dom_after = dom(browser_obj: browser_obj)
          diff_hash[:dom_after_step] = dom_after

          da = dom_before.to_a - dom_after.to_a
          diff_hash[:diff_dom] = da.to_h.transform_keys(&:to_sym)

          diff_arr.push(diff_hash)
        end

        diff_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.step_out(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   steps: 'optional - number of steps taken (Defaults to 1)'
      # )

      public_class_method def self.step_out(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)

        steps = opts[:steps].to_i
        steps = 1 if steps.zero? || steps.negative?

        diff_arr = []
        steps.times do |s|
          diff_hash = {}
          step = s + 1
          diff_hash[:step] = step

          dom_before = dom(browser_obj: browser_obj)
          diff_hash[:pre_step] = dom_before

          browser_obj[:devtools].send_cmd('Debugger.stepOut')

          dom_after = dom(browser_obj: browser_obj, step_sum: step_sum)
          diff_hash[:post_step] = dom_after

          da = dom_before.to_a - dom_after.to_a
          diff_hash[:diff] = da.to_h.transform_keys(&:to_sym)

          diff_arr.push(diff_hash)
        end

        diff_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.step_over(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   steps: 'optional - number of steps taken (Defaults to 1)'
      # )

      public_class_method def self.step_over(opts = {})
        browser_obj = opts[:browser_obj]
        supported = %i[chrome headless_chrome]
        verify_devtools_browser(browser_obj: browser_obj, supported: supported)

        steps = opts[:steps].to_i
        steps = 1 if steps.zero? || steps.negative?

        diff_arr = []
        steps.times do |s|
          diff_hash = {}
          step = s + 1
          diff_hash[:step] = step

          dom_before = dom(browser_obj: browser_obj)
          diff_hash[:dom_before_step] = dom_before

          browser_obj[:devtools].send_cmd('Debugger.stepOver')

          dom_after = dom(browser_obj: browser_obj, step_sum: step_sum)
          diff_hash[:dom_after_step] = dom_after

          da = dom_before.to_a - dom_after.to_a
          diff_hash[:diff_dom] = da.to_h.transform_keys(&:to_sym)

          diff_arr.push(diff_hash)
        end

        diff_arr
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.toggle_devtools(
      #   browser_obj: 'required - browser_obj returned from #open method)'
      # )

      public_class_method def self.toggle_devtools(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        # TODO: Find replacement for hotkey - there must be a better way.
        browser_obj[:browser].send_keys(:f12)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::TransparentBrowser.jmp_devtools_panel(
      #   browser_obj: 'required - browser_obj returned from #open method)',
      #   panel: 'optional - panel to switch to :elements|:inspector|:console|:debugger|:sources|:network
      # )

      public_class_method def self.jmp_devtools_panel(opts = {})
        browser_obj = opts[:browser_obj]
        verify_devtools_browser(browser_obj: browser_obj)

        panel = opts[:panel] ||= :elements
        browser = browser_obj[:browser]
        browser_type = browser_obj[:type]
        firefox_types = %i[firefox headless_firefox]
        chrome_types = %i[chrome headless_chrome]

        # TODO: Find replacement for hotkey - there must be a better way.
        hotkey = []
        case PWN::Plugins::DetectOS.type
        when :linux, :openbsd, :windows
          hotkey = %i[control shift]
        when :macos
          hotkey = %i[command option]
        end

        case panel
        when :elements, :inspector
          hotkey.push('i') if chrome_types.include?(browser_type)
          hotkey.push('c') if firefox_types.include?(browser_type)
        when :console
          hotkey.push('j') if chrome_types.include?(browser_type)
          hotkey.push('k') if firefox_types.include?(browser_type)
        when :debugger, :sources
          hotkey.push('s') if chrome_types.include?(browser_type)
          if firefox_types.include?(browser_type)
            # If we're in the console, we need to switch to the inspector first
            jmp_devtools_panel(browser_obj: browser_obj, panel: :inspector)
            sleep 1
            hotkey.push('z')
          end
        when :network
          hotkey.push('e') if firefox_types.include?(browser_type)
        else
          raise 'ERROR: panel parameter must be :elements|:inspector|:console|:debugger|:sources|:network'
        end

        browser_obj[:browser].send_keys(:escape)

        # Have to call twice for Chrome, otherwise devtools stays closed
        browser_obj[:browser].send_keys(hotkey)
        # browser.send_keys(hotkey) if chrome_types.include?(browser_type)
        browser.send_keys(:escape)
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
            devtools: 'optional - boolean (defaults to false)'
          )
          browser = browser_obj1[:browser]
          puts browser.public_methods

          ********************************************************
          * DevTools Interaction
          * All DevTools Commands can be found here:
          * https://chromedevtools.github.io/devtools-protocol/
          * Examples
          devtools = browser_obj1[:devtools]
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
            js: 'required - JavaScript expression to evaluate',
            return_to: 'optional - return to :console or :stdout (defaults to :console)'
          )

          console_resp = #{self}.view_dom_mutations(
            browser_obj: 'required - browser_obj returned from #open method)',
            index: 'optional - index of tab to switch to (defaults to active tab)',
            target: 'optional - target JavaScript node to observe (defaults to document.body)'
          )

          console_resp = #{self}.hide_dom_mutations(
            browser_obj: 'required - browser_obj returned from #open method)',
            index: 'optional - index of tab to switch to (defaults to active tab)'
          )

          #{self}.update_about_config(
            browser_obj: 'required - browser_obj returned from #open method)',
            key: 'required - key to update in about:config',
            value: 'required - value to set for key in about:config'
          )

          tabs = #{self}.list_tabs(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          tab = #{self}.jmp_tab(
            browser_obj: 'required - browser_obj returned from #open method)',
            index: 'optional - index of tab to switch to (defaults to switching to next tab)',
            keyword: 'optional - keyword in title or url used to switch tabs (defaults to switching to next tab)',
          )

          tab = #{self}.new_tab(
            browser_obj: 'required - browser_obj returned from #open method)',
            url: 'optional - URL to open in new tab'
          )

          tab = #{self}.close_tab(
            browser_obj: 'required - browser_obj returned from #open method)',
            index: 'optional - index of tab to close (defaults to closing active tab)',
            keyword: 'optional - keyword in title or url used to close tabs (defaults to closing active tab)'
          )

          #{self}.debugger(
            browser_obj: 'required - browser_obj returned from #open method)',
            action: 'optional - action to take :pause|:resume (Defaults to :pause)',
            url: 'optional - URL to navigate to after pausing debugger (Defaults to nil)'
          )

          current_dom = #{self}.dom(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          #{self}.step_into(
            browser_obj: 'required - browser_obj returned from #open method)',
            steps: 'optional - number of steps taken (Defaults to 1)'
          )

          #{self}.step_out(
            browser_obj: 'required - browser_obj returned from #open method)',
            steps: 'optional - number of steps taken (Defaults to 1)'
          )

          #{self}.step_over(
            browser_obj: 'required - browser_obj returned from #open method)',
            steps: 'optional - number of steps taken (Defaults to 1)'
          )

          #{self}.toggle_devtools(
            browser_obj: 'required - browser_obj returned from #open method)'
          )

          #{self}.jmp_devtools_panel(
            browser_obj: 'required - browser_obj returned from #open method)',
            panel: 'optional - panel to switch to :elements|:inspector|:console|:debugger|:sources|:network'
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
