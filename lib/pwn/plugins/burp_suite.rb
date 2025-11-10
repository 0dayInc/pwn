# frozen_string_literal: true

require 'base64'
require 'json'
require 'socket'
require 'uri'
require 'yaml'

module PWN
  module Plugins
    # This plugin was created to interact w/ Burp Suite Pro in headless mode to kick off spidering/live scanning
    module BurpSuite
      # Supported Method Parameters::
      # uri = PWN::Plugins::BurpSuite.format_uri_from_sitemap_resp(
      #   scheme: 'required - scheme of the URI (http|https)',
      #   host: 'required - host of the URI',
      #   port: 'optional - port of the URI',
      #   path: 'optional - path of the URI',
      #   query: 'optional - query string of the URI'
      # )
      private_class_method def self.format_uri_from_sitemap_resp(opts = {})
        scheme = opts[:scheme]
        raise 'ERROR: scheme parameter is required' if scheme.nil?

        host = opts[:host]
        raise 'ERROR: host parameter is required' if host.nil?

        port = opts[:port]
        path = opts[:path]
        query = opts[:query]

        implicit_http_ports_arr = [
          80,
          443
        ]

        uri = "#{scheme}://#{host}:#{port}#{path}"
        uri = "#{scheme}://#{host}#{path}" if implicit_http_ports_arr.include?(port)
        uri = "#{uri}?#{query}" unless query.nil?

        uri
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # burp_obj = PWN::Plugins::BurpSuite.init_introspection_thread(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   enumerable_array: 'required - array of items to process in the thread'
      # )
      private_class_method def self.init_introspection_thread(opts = {})
        #  if PWN::Env[:ai][:introspection] is true,
        #  spin up Thread to:
        #  1. Periodically call get_proxy_history(burp_obj: burp_obj) method
        #  2. For each entry w/ empty comment,
        #     generate AI analysis via PWN::AI::Introspection.reflect_on
        #     and populate the comment field for the entry.
        #  3. Update the highlight field based on EPSS score extracted from AI analysis.
        #  4. Call update_proxy_history(burp_obj: burp_obj, entry: updated_entry)
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        if PWN::Env[:ai][:introspection]
          introspection_thread = Thread.new do
            system_role_content = '
              Your expertise lies in dissecting HTTP request/response pairs to identify high-impact vulnerabilities, including but not limited to XSS (reflected, stored, DOM-based), CSRF, SSRF, IDOR, open redirects, CORS misconfigurations, authentication bypasses, SQLi/NoSQLi, command/code injection, business logic flaws, and API abuse. You prioritize zero-days and novel chains, always focusing on exploitability, impact (e.g., account takeover, data exfiltration, RCE), and reproducibility.

              When analyzing HTTP request/response pairs:

              1. **Parse and Contextualize Traffic**:
                 - Break down every element: HTTP method, URI (path, query parameters), headers (e.g., Host, User-Agent, Cookies, Authorization, Referer, Origin, Content-Type), request body (e.g., form data, JSON payloads), response status code, response headers, and response body (HTML, JSON, XML, etc.).
                 - Identify dynamic elements: User-controlled inputs (e.g., query params, POST data, headers like X-Forwarded-For), server-side echoes, redirects, and client-side processing.
                 - Trace data flow: Map how inputs propagate from request to response, including any client-side JavaScript execution where exploitation may be possible in the client without communicating with the server (e.g. DOM-XSS).

              2. **Vulnerability Hunting Framework**:
                 - **Input Validation & Sanitization**: Check for unescaped/lack of encoding in outputs (e.g., HTML context for XSS, URL context for open redirects).
                 - **XSS Focus**: Hunt for sinks like innerHTML/outerHTML, document.write, eval, setTimeout/setInterval with strings, location.href/assign/replace, and history.pushState. Test payloads like <script>alert(1)</script>, javascript:alert(1), and polyglots. For DOM-based, simulate client-side execution.
                 - **JavaScript Library Analysis**: If JS is present (e.g., in response body or referenced scripts), deobfuscate and inspect:
                   - Objects/properties that could clobber DOM (e.g., window.name, document.cookie manipulation leading to prototype pollution).
                   - DOM XSS vectors: Analyze event handlers, querySelector, addEventListener with unsanitized data from location.hash/search, postMessage, or localStorage.
                   - Third-party libs (e.g., jQuery, React): Flag known sink patterns like .html(), dangerouslySetInnerHTML, or eval-like functions.
                 - **Server-Side Issues**: Probe for SSRF (e.g., via URL params fetching internal resources), IDOR (e.g., manipulating IDs in paths/bodies), rate limiting bypass, and insecure deserialization (e.g., in JSON/PHP objects).
                 - **Headers & Misc**: Examine for exposed sensitive info (e.g., debug headers, stack traces), misconfigured security headers (CSP, HSTS), and upload flaws (e.g., file extension bypass).
                 - **Chaining Opportunities**: Always consider multi-step exploits, like XSS leading to CSRF token theft or SSRF to internal metadata endpoints.

              3. **PoC Generation**:
                 - Produce concise, step-by-step PoCs in a standardized format:
                   - **Description**: Clear vuln summary, CVSS-like severity, and impact.
                   - **Steps to Reproduce**: Numbered HTTP requests (use curl or Burp syntax, e.g., `curl -X POST -d "param=<payload>" https://target.com/endpoint`).
                   - **Payloads**: Provide working, minimal payloads with variations for evasion (e.g., encoded, obfuscated).
                   - **Screenshots/Evidence**: Suggest what to capture (e.g., alert popup for XSS, response diff for IDOR).
                   - **Mitigation Advice**: Recommend fixes (e.g., output encoding, input validation).
                 - Ensure PoCs are ethical: Target only in-scope assets, avoid DoS, and emphasize disclosure via proper channels (e.g., HackerOne, Bugcrowd).
                 - If no vuln found, explain why and suggest further tests (e.g., fuzzing params).
              4. Risk Score:
                For each analysis generate a risk score between 0% - 100% based on exploitability and impact.  This should be reflected as { "risk_score": "nnn%" } in the final output JSON.

              Analyze provided HTTP request/response pairs methodically: Start with a high-level overview, then dive into specifics, flag potential issues with evidence from the traffic, and end with PoC if applicable. Be verbose in reasoning but concise in output. Prioritize high-severity findings. If data is incomplete, request clarifications.
            '

            get_highlight_color = lambda do |opts = {}|
              ai_analysis = opts[:ai_analysis]

              highlight_color = 'GRAY'
              if ai_analysis =~ /"risk_score":\s*"(\d{1,3})%"/
                score = Regexp.last_match(1).to_i
                highlight_color = case score
                                  when 0..24
                                    'GREEN'
                                  when 25..49
                                    'YELLOW'
                                  when 50..74
                                    'ORANGE'
                                  when 75..100
                                    'RED'
                                  end
              end

              highlight_color
            end

            loop do
              # TODO: Implement sitemap and repeater into the loop.
              # Sitemap should work the same as proxy history.
              # Repeater should analyze the reqesut/response pair and suggest
              # modifications to the request to further probe for vulnerabilities.
              sitemap = get_sitemap(burp_obj: burp_obj)
              sitemap.each do |entry|
                next unless entry.key?(:comment) && entry[:comment].to_s.strip.empty?

                request = entry[:request]
                response = entry[:response]
                host = entry[:http_service][:host]
                port = entry[:http_service][:port]
                protocol = entry[:http_service][:protocol]
                next if request.nil? || response.nil? || host.nil? || port.nil? || protocol.nil?

                request = Base64.strict_decode64(request)
                response = Base64.strict_decode64(response)
                http_request_response = PWN::Plugins::Char.force_utf8("#{request}\r\n\r\n#{response}")
                ai_analysis = PWN::AI::Introspection.reflect_on(
                  system_role_content: system_role_content,
                  request: http_request_response,
                  suppress_pii_warning: true
                )

                next if ai_analysis.nil? || ai_analysis.strip.empty?

                entry[:comment] = ai_analysis
                entry[:highlight] = get_highlight_color.call(ai_analysis: ai_analysis)

                update_sitemap(
                  burp_obj: burp_obj,
                  entry: entry
                )
              end

              proxy_history = get_proxy_history(burp_obj: burp_obj)
              proxy_history.each do |entry|
                next unless entry.key?(:comment) && entry[:comment].to_s.strip.empty?

                request = entry[:request]
                response = entry[:response]
                host = entry[:http_service][:host]
                port = entry[:http_service][:port]
                protocol = entry[:http_service][:protocol]
                next if request.nil? || response.nil? || host.nil? || port.nil? || protocol.nil?

                request = Base64.strict_decode64(request)
                response = Base64.strict_decode64(response)

                # If sitemap comment and highlight color exists, use that instead of re-analyzing
                sitemap_entry = nil
                if sitemap.any?
                  sitemap_entry = sitemap.find do |site|
                    site[:http_service][:host] == host &&
                      site[:http_service][:port] == port &&
                      site[:http_service][:protocol] == protocol &&
                      site[:request] == entry[:request]
                  end
                end

                if sitemap_entry.nil?
                  http_request_response = PWN::Plugins::Char.force_utf8("#{request}\r\n\r\n#{response}")
                  ai_analysis = PWN::AI::Introspection.reflect_on(
                    system_role_content: system_role_content,
                    request: http_request_response,
                    suppress_pii_warning: true
                  )

                  next if ai_analysis.nil? || ai_analysis.strip.empty?

                  entry[:comment] = ai_analysis
                  entry[:highlight] = get_highlight_color.call(ai_analysis: ai_analysis)
                else
                  entry[:comment] = sitemap_entry[:comment]
                  entry[:highlight] = sitemap_entry[:highlight]
                end

                update_proxy_history(
                  burp_obj: burp_obj,
                  entry: entry
                )
              end
              sleep 3
            end
          rescue Errno::ECONNREFUSED
            puts 'Thread Terminating...'
          rescue StandardError => e
            puts "BurpSuite AI Introspection Thread Error: #{e}"
            puts e.backtrace
            raise e
          ensure
            puts 'BurpSuite AI Introspection Thread >>> Goodbye.'
          end

          burp_obj[:introspection_thread] = introspection_thread
        end

        burp_obj
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # burp_obj1 = PWN::Plugins::BurpSuite.start(
      #   burp_jar_path: 'optional - path of burp suite pro jar file (defaults to /opt/burpsuite/burpsuite_pro.jar)',
      #   headless: 'optional - run burp headless if set to true',
      #   browser_type: 'optional - defaults to :firefox. See PWN::Plugins::TransparentBrowser.help for a list of types',
      #   burp_ip: 'optional - IP address for the Burp proxy (defaults to 127.0.0.1)',
      #   burp_port: 'optional - port for the Burp proxy (defaults to a random unused port)',
      #   pwn_burp_ip: 'optional - IP address for the PWN Burp API (defaults to 127.0.0.1)',
      #   pwn_burp_port: 'optional - port for the PWN Burp API (defaults to a random unused port)'
      # )

      public_class_method def self.start(opts = {})
        burp_jar_path = opts[:burp_jar_path] ||= '/opt/burpsuite/burpsuite-pro.jar'
        raise "ERROR: #{burp_jar_path} not found." unless File.exist?(burp_jar_path)

        raise 'ERROR: /opt/burpsuite/pwn-burp.jar not found.  For more details about installing this extension, checkout https://github.com/0dayinc/pwn_burp' unless File.exist?('/opt/burpsuite/pwn-burp.jar')

        burp_root = File.dirname(burp_jar_path)

        headless = opts[:headless] || false
        browser_type = opts[:browser_type] ||= :firefox
        browser_type = browser_type.to_s.downcase.to_sym unless browser_type.is_a?(Symbol)
        browser_type = :headless if headless
        burp_ip = opts[:burp_ip] ||= '127.0.0.1'
        burp_port = opts[:burp_port] ||= PWN::Plugins::Sock.get_random_unused_port

        pwn_burp_ip = opts[:pwn_burp_ip] ||= '127.0.0.1'
        pwn_burp_port = opts[:pwn_burp_port] ||= PWN::Plugins::Sock.get_random_unused_port

        burp_cmd_string = 'java -Xms4G -Xmx16G'
        burp_cmd_string = "#{burp_cmd_string} -Djava.awt.headless=true" if headless
        burp_cmd_string = "#{burp_cmd_string} -Dproxy.address=#{burp_ip} -Dproxy.port=#{burp_port}"
        burp_cmd_string = "#{burp_cmd_string} -Dserver.address=#{pwn_burp_ip} -Dserver.port=#{pwn_burp_port}"
        burp_cmd_string = "#{burp_cmd_string} -jar #{burp_jar_path}"

        # Construct burp_obj
        burp_obj = {}
        burp_obj[:pid] = Process.spawn(burp_cmd_string, pgroup: true)
        browser_obj1 = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_browser = browser_obj1[:browser]

        burp_obj[:mitm_proxy] = "#{burp_ip}:#{burp_port}"
        burp_obj[:mitm_rest_api] = "#{pwn_burp_ip}:#{pwn_burp_port}"
        burp_obj[:rest_browser] = rest_browser

        # Proxy always listens on localhost...use SSH tunneling if remote access is required
        browser_obj2 = PWN::Plugins::TransparentBrowser.open(
          browser_type: browser_type,
          proxy: "http://#{burp_obj[:mitm_proxy]}",
          devtools: true
        )

        burp_obj[:mitm_browser] = browser_obj2

        # Wait for pwn_burp_port to open prior to returning burp_obj
        loop do
          s = TCPSocket.new(pwn_burp_ip, pwn_burp_port)
          s.close
          break
        rescue Errno::ECONNREFUSED
          print '.'
          sleep 3
          next
        end

        # Delete existing proxy listener and add new one
        # in favor of weird update behavior in event the port is alread in use
        # by another application which refuses to enable the listener even when
        # the port is changed via the update method.
        delete_proxy_listener(
          burp_obj: burp_obj,
          id: 0
        )

        add_proxy_listener(
          burp_obj: burp_obj,
          bindAddress: burp_ip,
          port: burp_port,
          enabled: true
        )

        init_introspection_thread(burp_obj: burp_obj)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # uri_in_scope = PWN::Plugins::BurpSuite.in_scope(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   uri: 'required - URI to determine if in scope'
      # )

      public_class_method def self.in_scope(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        uri = opts[:uri]
        raise 'ERROR: uri parameter is required' if uri.nil?

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        base64_encoded_uri = Base64.strict_encode64(uri.to_s.scrub.strip.chomp)

        in_scope_resp = rest_browser.get(
          "http://#{mitm_rest_api}/scope/#{base64_encoded_uri}",
          content_type: 'application/json; charset=UTF8'
        )
        json_in_scope = JSON.parse(in_scope_resp, symbolize_names: true)
        json_in_scope[:value]
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # json_in_scope = PWN::Plugins::BurpSuite.add_to_scope(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   target_url: 'required - target url to add to scope'
      # )

      public_class_method def self.add_to_scope(opts = {})
        burp_obj = opts[:burp_obj]
        target_url = opts[:target_url]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        post_body = { url: target_url }.to_json

        in_scope = rest_browser.post("http://#{mitm_rest_api}/scope", post_body, content_type: 'application/json; charset=UTF8')
        JSON.parse(in_scope, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_spider = PWN::Plugins::BurpSuite.spider(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   target_url: 'required - target url to add to crawl / spider'
      # )

      public_class_method def self.spider(opts = {})
        burp_obj = opts[:burp_obj]
        target_url = opts[:target_url]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        post_body = { url: target_url }.to_json

        in_scope = rest_browser.post(
          "http://#{mitm_rest_api}/spider",
          post_body,
          content_type: 'application/json; charset=UTF8'
        )
        spider_json = JSON.parse(in_scope, symbolize_names: true)
        spider_id = spider_json[:id]

        spider_status_json = {}
        loop do
          print '.'
          spider_status_resp = rest_browser.get("http://#{mitm_rest_api}/spider/#{spider_id}")
          spider_status_json = JSON.parse(spider_status_resp, symbolize_names: true)
          spider_status = spider_status_json[:status]
          case spider_status
          when 'queued', 'running'
            sleep 3
          when 'failed', 'finished'
            break
          else
            puts "Unknown spider status detected: #{spider_status}"
            break
          end
        end
        print "\n"

        spider_json.merge!(spider_status_json)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.enable_proxy(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.enable_proxy(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        enable_resp = rest_browser.post("http://#{mitm_rest_api}/proxy/intercept/enable", nil)
        JSON.parse(enable_resp, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.disable_proxy(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.disable_proxy(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        disable_resp = rest_browser.post("http://#{mitm_rest_api}/proxy/intercept/disable", nil)
        JSON.parse(disable_resp, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_proxy_listeners = PWN::Plugins::BurpSuite.get_proxy_listeners(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.get_proxy_listeners(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        listeners = rest_browser.get("http://#{mitm_rest_api}/proxy/listeners", content_type: 'application/json; charset=UTF8')
        JSON.parse(listeners, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_proxy_listener = PWN::Plugins::BurpSuite.add_proxy_listener(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   bindAddress: 'required - bind address for the proxy listener (e.g., "127.0.0.1")',
      #   port: 'required - port for the proxy listener (e.g., 8081)',
      #   enabled: 'optional - enable the listener (defaults to true)'
      # )

      public_class_method def self.add_proxy_listener(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        bind_address = opts[:bindAddress]
        raise 'ERROR: bindAddress parameter is required' if bind_address.nil?

        port = opts[:port]
        raise 'ERROR: port parameter is required' if port.nil?

        enabled = opts[:enabled] != false # Default to true if not specified

        proxy_listeners = get_proxy_listeners(burp_obj: burp_obj)
        last_known_proxy_id = 0
        last_known_proxy_id = proxy_listeners.last[:id].to_i if proxy_listeners.any?
        next_id = last_known_proxy_id + 1

        post_body = {
          id: next_id.to_s,
          bindAddress: bind_address,
          port: port,
          enabled: enabled
        }.to_json

        listener = rest_browser.post("http://#{mitm_rest_api}/proxy/listeners", post_body, content_type: 'application/json; charset=UTF8')
        JSON.parse(listener, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_proxy_listener = PWN::Plugins::BurpSuite.update_proxy_listener(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   id: 'optional - ID of the proxy listener (defaults to 0)',
      #   bindAddress: 'optional - bind address for the proxy listener (defaults to value of existing listener)',
      #   port: 'optional - port for the proxy listener (defaults to value of existing listener)',
      #   enabled: 'optional - enable or disable the listener (defaults to value of existing listener)'
      # )

      public_class_method def self.update_proxy_listener(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        id = opts[:id] ||= 0

        proxy_listeners = get_proxy_listeners(burp_obj: burp_obj)
        listener_by_id = proxy_listeners.find { |listener| listener[:id].to_i == id.to_i }
        raise "ERROR: No proxy listener found with ID #{id}" if listener_by_id.nil?

        bind_address = opts[:bindAddress] ||= listener_by_id[:bindAddress]
        port = opts[:port] ||= listener_by_id[:port]
        enabled = opts[:enabled] ||= listener_by_id[:enabled]

        post_body = {
          id: id.to_s,
          bindAddress: bind_address,
          port: port,
          enabled: enabled
        }.to_json

        listener = rest_browser.put("http://#{mitm_rest_api}/proxy/listeners/#{id}", post_body, content_type: 'application/json; charset=UTF8')
        JSON.parse(listener, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.delete_proxy_listener(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   id: 'optional - ID of the proxy listener (defaults to 0)'
      # )

      public_class_method def self.delete_proxy_listener(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        id = opts[:id] ||= 0
        proxy_listeners = get_proxy_listeners(burp_obj: burp_obj)
        listener_by_id = proxy_listeners.find { |listener| listener[:id].to_i == id.to_i }
        raise "ERROR: No proxy listener found with ID #{id}" if listener_by_id.nil?

        rest_browser.delete("http://#{mitm_rest_api}/proxy/listeners/#{id}")
        true # Return true to indicate successful deletion (or error if API fails)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_proxy_history = PWN::Plugins::BurpSuite.get_proxy_history(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   keyword: 'optional - keyword to filter proxy history entries (default: nil)',
      #   return_as: 'optional - :base64 or :har (defaults to :base64)'
      # )

      public_class_method def self.get_proxy_history(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        keyword = opts[:keyword]
        return_as = opts[:return_as] ||= :base64

        rest_call = "http://#{mitm_rest_api}/proxyhistory"

        sitemap = rest_browser.get(
          rest_call,
          content_type: 'application/json; charset=UTF8'
        )

        sitemap_arr = JSON.parse(sitemap, symbolize_names: true)

        if keyword
          sitemap_arr = sitemap_arr.select do |site|
            decoded_request = Base64.strict_decode64(site[:request])
            decoded_request.include?(keyword)
          end
        end

        if return_as == :har
          # Convert to HAR format
          har_entries = sitemap_arr.map do |site|
            decoded_request = Base64.strict_decode64(site[:request])

            # Parse request head and body
            if decoded_request.include?("\r\n\r\n")
              request_head, request_body = decoded_request.split("\r\n\r\n", 2)
            else
              request_head = decoded_request
              request_body = ''
            end
            request_lines = request_head.split("\r\n")
            request_line = request_lines.shift
            method, full_path, http_version = request_line.split(' ', 3)
            headers = {}
            request_lines.each do |line|
              next if line.empty?

              key, value = line.split(': ', 2)
              headers[key] = value if key && value
            end

            host = headers['Host'] || raise('No Host header found in request')
            scheme = 'http' # Hardcoded as protocol is not available; consider enhancing if available in site
            url = "#{scheme}://#{host}#{full_path}"
            uri = URI.parse(url)
            query_string = uri.query ? URI.decode_www_form(uri.query).map { |k, v| { name: k, value: v.to_s } } : []

            request_headers_size = request_head.bytesize + 4 # Account for \r\n\r\n
            request_body_size = request_body.bytesize

            request_obj = {
              method: method,
              url: uri.to_s,
              httpVersion: http_version,
              headers: headers.map { |k, v| { name: k, value: v } },
              queryString: query_string,
              headersSize: request_headers_size,
              bodySize: request_body_size
            }

            if request_body_size.positive?
              mime_type = headers['Content-Type'] || 'application/octet-stream'
              post_data = {
                mimeType: mime_type,
                text: request_body
              }
              post_data[:params] = URI.decode_www_form(request_body).map { |k, v| { name: k, value: v.to_s } } if mime_type.include?('x-www-form-urlencoded')
              request_obj[:postData] = post_data
            end

            if site[:response]
              decoded_response = Base64.strict_decode64(site[:response])

              # Parse response head and body
              if decoded_response.include?("\r\n\r\n")
                response_head, response_body = decoded_response.split("\r\n\r\n", 2)
              else
                response_head = decoded_response
                response_body = ''
              end
              response_lines = response_head.split("\r\n")
              status_line = response_lines.shift
              version, status_str, status_text = status_line.split(' ', 3)
              status = status_str.to_i
              status_text ||= ''
              response_headers = {}
              response_lines.each do |line|
                next if line.empty?

                key, value = line.split(': ', 2)
                response_headers[key] = value if key && value
              end

              response_headers_size = response_head.bytesize + 4 # Account for \r\n\r\n
              response_body_size = response_body.bytesize
              mime_type = response_headers['Content-Type'] || 'text/plain'

              response_obj = {
                status: status,
                statusText: status_text,
                httpVersion: version,
                headers: response_headers.map { |k, v| { name: k, value: v } },
                content: {
                  size: response_body_size,
                  mimeType: mime_type,
                  text: response_body
                },
                redirectURL: response_headers['Location'] || '',
                headersSize: response_headers_size,
                bodySize: response_body_size
              }
            else
              response_obj = {
                status: 0,
                statusText: 'No response',
                httpVersion: 'unknown',
                headers: [],
                content: {
                  size: 0,
                  mimeType: 'text/plain',
                  text: ''
                },
                redirectURL: '',
                headersSize: -1,
                bodySize: 0
              }
            end

            {
              startedDateTime: Time.now.iso8601,
              time: 0,
              request: request_obj,
              response: response_obj,
              cache: {},
              timings: {
                send: 0,
                wait: 0,
                receive: 0
              },
              pageref: 'page_1'
            }
          end

          har_log = {
            log: {
              version: '1.2',
              creator: {
                name: 'BurpSuite via PWN::Plugins::BurpSuite',
                version: '1.0'
              },
              pages: [{
                startedDateTime: Time.now.iso8601,
                id: 'page_1',
                title: 'Sitemap Export',
                pageTimings: {}
              }],
              entries: har_entries
            }
          }

          sitemap_arr = har_log
        end

        sitemap_arr.uniq
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_proxy_history = PWN::Plugins::BurpSuite.update_proxy_history(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   entry: 'required - hash of the proxy history entry to update'
      # )

      public_class_method def self.update_proxy_history(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        entry = opts[:entry]
        raise 'ERROR: entry parameter is required and must be a hash' unless entry.is_a?(Hash)

        id = entry[:id]
        raise 'ERROR: id key value pair is required within entry hash' if id.nil?

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        # Only allow updating of comment and highlight fields
        entry.delete(:request)
        entry.delete(:response)
        entry.delete(:http_service)

        put_body = entry.to_json

        proxy_history_resp = rest_browser.put(
          "http://#{mitm_rest_api}/proxyhistory/#{id}",
          put_body,
          content_type: 'application/json; charset=UTF8'
        )

        JSON.parse(proxy_history_resp, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # json_sitemap = PWN::Plugins::BurpSuite.get_sitemap(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   keyword: 'optional - keyword to filter sitemap entries (default: nil)',
      #   return_as: 'optional - :base64 or :har (defaults to :base64)'
      # )

      public_class_method def self.get_sitemap(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        keyword = opts[:keyword]
        return_as = opts[:return_as] ||= :base64

        rest_call = "http://#{mitm_rest_api}/sitemap"

        sitemap = rest_browser.get(
          rest_call,
          content_type: 'application/json; charset=UTF8'
        )

        sitemap_arr = JSON.parse(sitemap, symbolize_names: true)

        if keyword
          sitemap_arr = sitemap_arr.select do |site|
            decoded_request = Base64.strict_decode64(site[:request])
            decoded_request.include?(keyword)
          end
        end

        if return_as == :har
          # Convert to HAR format
          har_entries = sitemap_arr.map do |site|
            decoded_request = Base64.strict_decode64(site[:request])

            # Parse request head and body
            if decoded_request.include?("\r\n\r\n")
              request_head, request_body = decoded_request.split("\r\n\r\n", 2)
            else
              request_head = decoded_request
              request_body = ''
            end
            request_lines = request_head.split("\r\n")
            request_line = request_lines.shift
            method, full_path, http_version = request_line.split(' ', 3)
            headers = {}
            request_lines.each do |line|
              next if line.empty?

              key, value = line.split(': ', 2)
              headers[key] = value if key && value
            end

            host = headers['Host'] || raise('No Host header found in request')
            scheme = 'http' # Hardcoded as protocol is not available; consider enhancing if available in site
            url = "#{scheme}://#{host}#{full_path}"
            uri = URI.parse(url)
            query_string = uri.query ? URI.decode_www_form(uri.query).map { |k, v| { name: k, value: v.to_s } } : []

            request_headers_size = request_head.bytesize + 4 # Account for \r\n\r\n
            request_body_size = request_body.bytesize

            request_obj = {
              method: method,
              url: uri.to_s,
              httpVersion: http_version,
              headers: headers.map { |k, v| { name: k, value: v } },
              queryString: query_string,
              headersSize: request_headers_size,
              bodySize: request_body_size
            }

            if request_body_size.positive?
              mime_type = headers['Content-Type'] || 'application/octet-stream'
              post_data = {
                mimeType: mime_type,
                text: request_body
              }
              post_data[:params] = URI.decode_www_form(request_body).map { |k, v| { name: k, value: v.to_s } } if mime_type.include?('x-www-form-urlencoded')
              request_obj[:postData] = post_data
            end

            if site[:response]
              decoded_response = Base64.strict_decode64(site[:response])

              # Parse response head and body
              if decoded_response.include?("\r\n\r\n")
                response_head, response_body = decoded_response.split("\r\n\r\n", 2)
              else
                response_head = decoded_response
                response_body = ''
              end
              response_lines = response_head.split("\r\n")
              status_line = response_lines.shift
              version, status_str, status_text = status_line.split(' ', 3)
              status = status_str.to_i
              status_text ||= ''
              response_headers = {}
              response_lines.each do |line|
                next if line.empty?

                key, value = line.split(': ', 2)
                response_headers[key] = value if key && value
              end

              response_headers_size = response_head.bytesize + 4 # Account for \r\n\r\n
              response_body_size = response_body.bytesize
              mime_type = response_headers['Content-Type'] || 'text/plain'

              response_obj = {
                status: status,
                statusText: status_text,
                httpVersion: version,
                headers: response_headers.map { |k, v| { name: k, value: v } },
                content: {
                  size: response_body_size,
                  mimeType: mime_type,
                  text: response_body
                },
                redirectURL: response_headers['Location'] || '',
                headersSize: response_headers_size,
                bodySize: response_body_size
              }
            else
              response_obj = {
                status: 0,
                statusText: 'No response',
                httpVersion: 'unknown',
                headers: [],
                content: {
                  size: 0,
                  mimeType: 'text/plain',
                  text: ''
                },
                redirectURL: '',
                headersSize: -1,
                bodySize: 0
              }
            end

            {
              startedDateTime: Time.now.iso8601,
              time: 0,
              request: request_obj,
              response: response_obj,
              cache: {},
              timings: {
                send: 0,
                wait: 0,
                receive: 0
              },
              pageref: 'page_1'
            }
          end

          har_log = {
            log: {
              version: '1.2',
              creator: {
                name: 'BurpSuite via PWN::Plugins::BurpSuite',
                version: '1.0'
              },
              pages: [{
                startedDateTime: Time.now.iso8601,
                id: 'page_1',
                title: 'Sitemap Export',
                pageTimings: {}
              }],
              entries: har_entries
            }
          }

          sitemap_arr = har_log
        end

        sitemap_arr.uniq
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters:
      # json_sitemap = PWN::Plugins::BurpSuite.add_to_sitemap(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   sitemap: 'required - sitemap hash to add',
      #   debug: 'optional - boolean to enable sitemap debugging (default: false)'
      # )
      #
      # Example:
      # json_sitemap = PWN::Plugins::BurpSuite.add_to_sitemap(
      #   burp_obj: burp_obj,
      #   sitemap: {
      #     request: 'base64_encoded_request_string',
      #     response: 'base64_encoded_response_string',
      #     highlight: 'NONE'||'RED'||'ORANGE'||'YELLOW'||'GREEN'||'CYAN'||'BLUE'||'PINK'||'MAGENTA'||'GRAY',
      #     comment: 'optional comment for the sitemap entry',
      #     http_service: {
      #       host: 'example.com',
      #       port: 80,
      #       protocol: 'http'
      #     }
      #   }

      public_class_method def self.add_to_sitemap(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        sitemap = opts[:sitemap] ||= {}
        debug = opts[:debug] || false

        rest_client = rest_browser::Request
        response = rest_client.execute(
          method: :post,
          url: "http://#{mitm_rest_api}/sitemap",
          payload: sitemap.to_json,
          headers: { content_type: 'application/json; charset=UTF-8' },
          timeout: 10
        )

        if debug
          puts "\nSubmitted:"
          puts sitemap.inspect
          print 'Press Enter to continue...'
          gets
        end
        # Return response body (assumed to be JSON)
        JSON.parse(response.body, symbolize_names: true)
      rescue RestClient::ExceptionWithResponse => e
        puts "ERROR: Failed to add to sitemap: #{e.message}"
        puts "HTTP error adding to sitemap: Status #{e.response.code}, Response: #{e.response.body}" if e.respond_to?(:response) && e.response.respond_to?(:code) && e.response.respond_to?(:body)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_sitemap = PWN::Plugins::BurpSuite.update_sitemap(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   entry: 'required - hash of the sitemap entry to update'
      # )

      public_class_method def self.update_sitemap(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        entry = opts[:entry]
        raise 'ERROR: entry parameter is required and must be a hash' unless entry.is_a?(Hash)

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        # Only allow updating of comment and highlight fields
        # NOTE we need the request as its used to identify the sitemap entry to update
        entry.delete(:response)
        entry.delete(:http_service)

        put_body = entry.to_json

        sitemap_resp = rest_browser.put(
          "http://#{mitm_rest_api}/sitemap",
          put_body,
          content_type: 'application/json; charset=UTF8'
        )

        JSON.parse(sitemap_resp, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters:
      # json_sitemap = PWN::Plugins::BurpSuite.import_openapi_to_sitemap(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   openapi_spec: 'required - path to OpenAPI JSON or YAML specification file',
      #   additional_http_headers: 'optional - hash of additional HTTP headers to include in requests (default: {})',
      #   highlight: 'optional - highlight color for the sitemap entry (default: "NONE")',
      #   comment: 'optional - comment for the sitemap entry (default: "")',
      #   debug: 'optional - boolean to enable debug logging (default: false)'
      # )
      public_class_method def self.import_openapi_to_sitemap(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        openapi_spec = opts[:openapi_spec]
        raise 'ERROR: openapi_spec parameter is required' if openapi_spec.nil?

        additional_http_headers = opts[:additional_http_headers] ||= {}
        raise 'ERROR: additional_http_headers must be a Hash' unless additional_http_headers.is_a?(Hash)

        highlight = opts[:highlight] ||= 'NONE'
        comment = opts[:comment].to_s.scrub

        debug = opts[:debug] || false

        openapi_spec_root = File.dirname(openapi_spec)
        Dir.chdir(openapi_spec_root)

        # Parse the OpenAPI JSON or YAML specification file
        # If the openapi_spec is YAML, convert it to JSON
        openapi = if openapi_spec.end_with?('.json')
                    JSON.parse(File.read(openapi_spec), symbolize_names: true)
                  elsif openapi_spec.end_with?('.yaml', '.yml')
                    YAML.safe_load_file(openapi_spec, permitted_classes: [Symbol, Date, Time], aliases: true, symbolize_names: true)
                  else
                    raise "ERROR: Unsupported file extension for #{openapi_spec}. Expected .json, .yaml, or .yml."
                  end

        # Initialize result array
        sitemap_arr = []

        # Get servers; default to empty array if not present
        servers = openapi[:servers].is_a?(Array) ? openapi[:servers] : []
        if servers.empty?
          warn("No servers defined in #{openapi_spec}. Using default server 'http://localhost'.")
          servers = [{ url: 'http://localhost', description: 'Default server' }]
        end

        # Valid HTTP methods for validation
        valid_methods = %w[get post put patch delete head options trace connect]

        # Helper lambda to resolve $ref in schemas
        resolve_ref = lambda do |openapi, ref|
          return nil unless ref&.start_with?('#/')

          parts = ref.sub('#/', '').split('/')
          resolved = openapi
          parts.each do |part|
            resolved = resolved[part.to_sym]
            return nil unless resolved
          end
          resolved
        end

        # Iterate through each server
        servers.each do |server|
          server_url = server[:url]
          unless server_url.is_a?(String)
            warn("[ERROR] Invalid server URL type '#{server_url.class}' in #{openapi_spec}: Expected String, got #{server_url.inspect}")
            next
          end

          begin
            uri = URI.parse(server_url)
            host = uri.host
            port = uri.port
            protocol = uri.scheme
            server_path = uri.path&.sub(%r{^/+}, '')&.sub(%r{/+$}, '') || ''

            warn("[DEBUG] Processing server: #{server_url}, host: #{host}, port: #{port}, protocol: #{protocol}, server_path: #{server_path}") if debug

            # Iterate through each path and its methods
            openapi[:paths]&.each do |path, methods|
              # Convert path to string, handling different types
              path_str = case path
                         when Symbol, String
                           path.to_s
                         else
                           warn("[ERROR] Invalid path type '#{path.class}' in #{openapi_spec}: Expected Symbol or String, got #{path.inspect}")
                           '/' # Fallback to root path
                         end

              # Construct full path by prepending server path if present
              full_path = server_path.empty? ? path_str : "/#{server_path}/#{path_str.sub(%r{^/+}, '')}".gsub(%r{/+}, '/')

              # Initialize path-level parameters
              path_parameters = []

              # Process methods based on type
              operations = []
              if methods.is_a?(Hash)
                # Extract path-level parameters
                path_parameters = methods[:parameters].is_a?(Array) ? methods[:parameters] : []
                warn("[DEBUG] Path-level parameters for #{full_path}: #{path_parameters.inspect}") if debug && !path_parameters.empty?

                # Collect operations for valid HTTP methods
                methods.each do |method, details|
                  method_str = case method
                               when Symbol, String
                                 method.to_s.downcase
                               else
                                 warn("[ERROR] Invalid method type '#{method.class}' for path '#{full_path}' in #{openapi_spec}: Expected Symbol or String, got #{method.inspect}")
                                 nil
                               end

                  next unless method_str && valid_methods.include?(method_str)

                  operations << { method: method_str, details: details }
                end
              elsif methods.is_a?(Array)
                warn("[DEBUG] Methods is an array for path '#{full_path}' in #{openapi_spec}: #{methods.inspect}") if debug

                # Look for parameters in the array
                param_entry = methods.find { |m| m.is_a?(Hash) && m[:parameters].is_a?(Array) }
                path_parameters = param_entry[:parameters] if param_entry
                warn("[DEBUG] Path-level parameters for #{full_path}: #{path_parameters.inspect}") if debug && !path_parameters.empty?

                # Collect operations from array elements
                methods.each do |op|
                  next unless op.is_a?(Hash)

                  # Infer method from operationId or other indicators
                  method_str = if op[:operationId].is_a?(String)
                                 op_id = op[:operationId].downcase
                                 valid_methods.find { |m| op_id.start_with?(m) }
                               elsif op[:method].is_a?(String) || op[:method].is_a?(Symbol)
                                 op[:method].to_s.downcase if valid_methods.include?(op[:method].to_s.downcase)
                               end

                  if method_str
                    operations << { method: method_str, details: op }
                  else
                    warn("[ERROR] Could not infer valid HTTP method for operation #{op.inspect} in path '#{full_path}' in #{openapi_spec}")
                  end
                end
              else
                warn("[ERROR] Invalid methods type '#{methods.class}' for path '#{full_path}' in #{openapi_spec}: Expected Hash or Array, got #{methods.inspect}")
              end

              # Process each operation
              operations.each do |op|
                method_str = op[:method]
                details = op[:details]

                # Handle details based on type
                operation = case details
                            when Hash
                              details
                            when Array
                              # Find the first hash with responses, or use empty hash
                              selected = details.find { |d| d.is_a?(Hash) && d[:responses].is_a?(Hash) }
                              if selected
                                selected
                              else
                                warn("[ERROR] No valid operation hash found in array for #{method_str.upcase} #{full_path} in #{openapi_spec}: Got #{details.inspect}")
                                {}
                              end
                            else
                              warn("[ERROR] Invalid details type '#{details.class}' for #{method_str.upcase} #{full_path} in #{openapi_spec}: Expected Hash or Array, got #{details.inspect}")
                              {}
                            end

                # Skip if operation is empty (indicating invalid details)
                if operation.empty?
                  warn("[DEBUG] Skipping #{method_str.upcase} #{full_path} due to invalid operation data") if debug
                  next
                end

                # Skip if no valid responses
                unless operation[:responses].is_a?(Hash)
                  warn("[ERROR] No valid responses for #{method_str.upcase} #{full_path} in #{openapi_spec}: Expected Hash, got #{operation[:responses].inspect}")
                  next
                end

                begin
                  # Construct HTTP request headers
                  request_headers = {
                    host: host
                  }
                  request_headers.merge!(additional_http_headers)

                  # Combine path-level and operation-level parameters
                  operation_parameters = operation[:parameters].is_a?(Array) ? operation[:parameters] : []
                  all_parameters = path_parameters + operation_parameters
                  warn("[DEBUG] All parameters for #{method_str.upcase} #{full_path}: #{all_parameters.inspect}") if debug && !all_parameters.empty?

                  # Determine response code from operation[:responses].keys
                  fallback_response_code = 200
                  response_keys = operation[:responses].keys
                  response_key = response_keys.find { |key| key.to_s.to_i.between?(100, 599) } || fallback_response_code.to_s
                  response_code = response_key.to_s.to_i

                  # Construct response body from operation responses schema example, schema $ref example, etc.
                  response_obj = operation[:responses][response_key] || {}
                  content = response_obj[:content] || {}
                  content_type = content.keys.first&.to_s || 'text/plain'

                  response_body = ''
                  unless [204, 304].include?(response_code)
                    content_obj = content[content_type.to_sym] || {}
                    example = content_obj[:example]
                    if example.nil? && content_obj[:examples].is_a?(Hash)
                      ex_key = content_obj[:examples].keys.first
                      if ex_key
                        ex = content_obj[:examples][ex_key]
                        if ex[:$ref]
                          resolved_ex = resolve_ref.call(openapi, ex[:$ref])
                          example = resolved_ex[:value] if resolved_ex
                        else
                          example = ex[:value]
                        end
                      end
                    end

                    if example.nil?
                      schema = content_obj[:schema]
                      if schema
                        if schema[:$ref]
                          ref = schema[:$ref]
                          if ref.start_with?('#/')
                            parts = ref.sub('#/', '').split('/')
                            resolved = openapi
                            parts.each do |part|
                              resolved = resolved[part.to_sym]
                              break unless resolved
                            end
                            schema = resolved if resolved
                          end
                        end

                        example = schema[:example]
                        if example.nil? && schema[:examples].is_a?(Hash)
                          ex_key = schema[:examples].keys.first
                          if ex_key
                            ex = schema[:examples][ex_key]
                            if ex[:$ref]
                              resolved_ex = resolve_ref.call(openapi, ex[:$ref])
                              example = resolved_ex[:value] if resolved_ex
                            else
                              example = ex[:value]
                            end
                          end
                        end
                      end
                    end

                    response_body = example || response_obj[:description] || "INFO: Unable to resolve response body from #{openapi_spec} => { 'http_method': '#{method_str.upcase}', 'path': '#{full_path}', 'response_code': '#{response_code}' }"
                  end

                  # Try to extract query samples from response example if it's a links object
                  query_hash = nil
                  if response_body.is_a?(Hash) && response_body[:links]
                    href = response_body.dig(:links, :self, :href)
                    # href ||= response_body[:links].values.first&.dig(:href) rescue nil
                    if href.nil? && response_body[:links].is_a?(Hash) && !response_body[:links].empty?
                      first_value = response_body[:links].values.first
                      href = first_value[:href] if first_value.is_a?(Hash)
                    end
                    if href
                      begin
                        parsed_uri = URI.parse(href)
                        query_hash = URI.decode_www_form(parsed_uri.query).to_h if parsed_uri.path.end_with?(path_str) && parsed_uri.query
                      rescue URI::InvalidURIError => e
                        warn("[DEBUG] Invalid href in response example: #{href} - #{e.message}") if debug
                      end
                    end
                  end

                  # Process path parameters for substitution
                  request_path = full_path.dup
                  query_params = []

                  all_parameters.each do |param|
                    next unless param.is_a?(Hash) && param[:name] && param[:in]

                    param_name = param[:name].to_s

                    # Get param_value with precedence: param.examples > param.example > schema.examples > schema.example > 'FUZZ'
                    param_value = if param[:examples].is_a?(Hash) && !param[:examples].empty?
                                    first_ex = param[:examples].values.first
                                    if first_ex.is_a?(Hash)
                                      if first_ex[:$ref]
                                        # Resolve $ref for example if present
                                        resolved_ex = resolve_ref.call(openapi, first_ex[:$ref])
                                        resolved_ex[:value] if resolved_ex
                                      else
                                        first_ex[:value]
                                      end
                                    else
                                      first_ex
                                    end || 'FUZZ'
                                  elsif param.key?(:example)
                                    param[:example]
                                  else
                                    schema = param[:schema]
                                    if schema
                                      if schema[:$ref]
                                        resolved_schema = resolve_ref.call(openapi, schema[:$ref])
                                        schema = resolved_schema if resolved_schema
                                      end
                                      if schema[:examples].is_a?(Hash) && !schema[:examples].empty?
                                        first_ex = schema[:examples].values.first
                                        if first_ex.is_a?(Hash)
                                          if first_ex[:$ref]
                                            resolved_ex = resolve_ref.call(openapi, first_ex[:$ref])
                                            resolved_ex[:value] if resolved_ex
                                          else
                                            first_ex[:value]
                                          end
                                        else
                                          first_ex
                                        end || 'FUZZ'
                                      elsif schema.key?(:example)
                                        schema[:example]
                                      else
                                        'FUZZ'
                                      end
                                    else
                                      'FUZZ'
                                    end
                                  end

                    # If still 'FUZZ' and it's a query param, try to get from response example query_hash
                    param_value = query_hash[param_name] if param_value == 'FUZZ' && param[:in] == 'query' && query_hash&.key?(param_name)

                    case param[:in]
                    when 'header'
                      # Aggregate remaining HTTP header names from spec,
                      # reference as keys, and assign their respective
                      # values to the request_headers hash
                      param_key = param_name.downcase
                      request_headers[param_key] = param_value.to_s
                    when 'path'
                      # Substitute path parameter with the resolved value
                      request_path.gsub!("{#{param_name}}", param_value.to_s)
                    when 'query'
                      # Collect query parameters
                      query_params.push("#{URI.encode_www_form_component(param_name)}=#{URI.encode_www_form_component(param_value.to_s)}")
                    end
                  end

                  # Append query parameters to path if any
                  request_path += "?#{query_params.join('&')}" if query_params.any?

                  # Construct request lines, including all headers
                  request_lines = [
                    "#{method_str.upcase} #{request_path} HTTP/1.1"
                  ]
                  request_headers.each do |key, value|
                    # Capitalize header keys (e.g., 'host' to 'Host', 'authorization' to 'Authorization')
                    header_key = key.to_s.split('-').map(&:capitalize).join('-')
                    request_lines.push("#{header_key}: #{value}")
                  end
                  request_lines << '' << '' # Add blank lines for HTTP request body separation

                  request = request_lines.join("\r\n")
                  encoded_request = Base64.strict_encode64(request)

                  response_status = case response_code
                                    when 200 then '200 OK'
                                    when 201 then '201 Created'
                                    when 204 then '204 No Content'
                                    when 301 then '301 Moved Permanently'
                                    when 302 then '302 Found'
                                    when 303 then '303 See Other'
                                    when 304 then '304 Not Modified'
                                    when 307 then '307 Temporary Redirect'
                                    when 308 then '308 Permanent Redirect'
                                    when 400 then '400 Bad Request'
                                    when 401 then '401 Unauthorized'
                                    when 403 then '403 Forbidden'
                                    when 404 then '404 Not Found'
                                    when 500 then '500 Internal Server Error'
                                    when 502 then '502 Bad Gateway'
                                    when 503 then '503 Service Unavailable'
                                    when 504 then '504 Gateway Timeout'
                                    else "#{fallback_response_code} OK"
                                    end

                  # Serialize response_body based on content_type
                  if content_type =~ /json/i && (response_body.is_a?(Hash) || response_body.is_a?(Array))
                    response_body = JSON.generate(response_body)
                  else
                    response_body = response_body.to_s
                  end

                  response_lines = [
                    "HTTP/1.1 #{response_status}",
                    "Content-Type: #{content_type}",
                    "Content-Length: #{response_body.length}",
                    '',
                    response_body
                  ]
                  response = response_lines.join("\r\n")
                  encoded_response = Base64.strict_encode64(response)

                  # Build the hash for this endpoint
                  sitemap_hash = {
                    request: encoded_request,
                    response: encoded_response,
                    highlight: highlight.to_s.upcase,
                    comment: comment,
                    http_service: {
                      host: host,
                      port: port,
                      protocol: protocol
                    }
                  }

                  # Add to the results array
                  sitemap_arr.push(sitemap_hash)
                  warn("[DEBUG] Added sitemap entry for #{method_str.upcase} #{request_path} on #{server_url} with headers #{request_headers.inspect}") if debug
                rescue StandardError => e
                  warn("[ERROR] Failed to process #{method_str.upcase} #{full_path} on #{server_url}: #{e.message}")
                  warn("[DEBUG] Operation: #{operation.inspect}, Parameters: #{all_parameters.inspect}, Headers: #{request_headers.inspect}") if debug
                end
              end
            end
          rescue URI::InvalidURIError => e
            warn("[ERROR] Invalid server URL '#{server_url}' in #{openapi_spec}: #{e.message}")
          end
        end

        sitemap_arr.each do |sitemap|
          add_to_sitemap(burp_obj: burp_obj, sitemap: sitemap)
        rescue RestClient::ExceptionWithResponse => e
          puts e.message
          next
        end

        sitemap_arr
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # active_scan_url_arr = PWN::Plugins::BurpSuite.active_scan(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   target_url: 'required - target url to scan in sitemap (should be loaded & authenticated w/ burp_obj[:mitm_browser])',
      #   exclude_paths: 'optional - array of paths to exclude from active scan (default: [])'
      # )

      public_class_method def self.active_scan(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        target_url = opts[:target_url].to_s.scrub.strip.chomp
        raise 'ERROR: target_url parameter is required' if target_url.empty?

        exclude_paths = opts[:exclude_paths] ||= []

        target_scheme = URI.parse(target_url).scheme
        target_host = URI.parse(target_url).host
        target_path = URI.parse(target_url).path
        target_port = URI.parse(target_url).port.to_i
        active_scan_url_arr = []

        json_sitemap = get_sitemap(burp_obj: burp_obj, target_url: target_url)
        json_sitemap.uniq.each do |site|
          # Skip if the site does not have a request or http_service
          next if site[:request].empty?

          json_req = site[:request]
          b64_decoded_req = Base64.strict_decode64(json_req)
          json_path = b64_decoded_req.split[1].to_s.scrub.strip.chomp
          next if exclude_paths.include?(json_path)

          json_query = json_path.split('?')[1].to_s.scrub.strip.chomp

          json_http_svc = site[:http_service]
          json_protocol = json_http_svc[:protocol]
          json_host = json_http_svc[:host].to_s.scrub.strip.chomp
          json_port = json_http_svc[:port].to_i

          json_uri = format_uri_from_sitemap_resp(
            scheme: json_protocol,
            host: json_host,
            port: json_port,
            path: json_path,
            query: json_query
          )

          uri_in_scope = in_scope(
            burp_obj: burp_obj,
            uri: json_uri
          )

          puts "Skipping #{json_uri} - not in scope. Check out #{self}.help >>  #add_to_scope method" unless uri_in_scope
          next unless uri_in_scope

          # If the protocol is HTTPS, set use_https to true
          use_https = false
          use_https = true if json_protocol == 'https'

          print "Adding #{json_uri} to Active Scan"
          active_scan_url_arr.push(json_uri)
          post_body = {
            host: json_host,
            port: json_port,
            use_https: use_https,
            request: json_req
          }.to_json
          # Kick off an active scan for each given page in the json_sitemap results
          resp = rest_browser.post(
            "http://#{mitm_rest_api}/scan/active",
            post_body,
            content_type: 'application/json'
          )
          puts " => #{resp.code}"
        rescue RestClient::ExceptionWithResponse => e
          puts " => #{e.response.code}" if e.respond_to?(:response) && e.response
          next
        end

        # Wait for scan completion
        loop do
          scan_queue = rest_browser.get("http://#{mitm_rest_api}/scan/active")
          json_scan_queue = JSON.parse(scan_queue, symbolize_names: true)
          break if json_scan_queue.all? { |scan| scan[:status] == 'finished' }

          puts "\n\n\n"
          puts '-' * 90
          json_scan_queue.each do |scan|
            puts "Target ID: #{scan[:id]}, Request Count: #{scan[:request_count]}, Progress: #{scan[:percent_complete]}%, Status: #{scan[:status]}"
          end

          sleep 30
        end
        # scan_queue_total = json_scan_queue.count
        # json_scan_queue.each do |scan_item|
        #   this_scan_item_id = scan_item[:id]
        #   until scan_item[:status] == 'finished'
        #     scan_item_resp = rest_browser.get("http://#{mitm_rest_api}/scan/active/#{this_scan_item_id}")
        #     scan_item = JSON.parse(scan_item_resp, symbolize_names: true)
        #     scan_status = scan_item[:status]
        #     puts "Target ID ##{this_scan_item_id} of ##{scan_queue_total}| #{scan_status}"
        #     sleep 3
        #   end
        #   puts "Target ID ##{this_scan_item_id} of ##{scan_queue_total}| 100% complete\n"
        # end

        active_scan_url_arr # Return array of targeted URIs to pass to #generate_scan_report method
      rescue StandardError => e
        # stop(burp_obj: burp_obj) unless burp_obj.nil?
        puts e.backtrace
        raise e
      end

      # Supported Method Parameters::
      # json_scan_issues = PWN::Plugins::BurpSuite.get_scan_issues(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.get_scan_issues(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        rest_client = rest_browser::Request
        scan_issues = rest_client.execute(
          method: :get,
          url: "http://#{mitm_rest_api}/scanissues",
          timeout: 540
        )
        JSON.parse(scan_issues, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # repeater_id = PWN::Plugins::BurpSuite.add_repeater_tab(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   name: 'required - name of the repeater tab (max 30 characters)',
      #   request: 'optional - base64 encoded HTTP request string'
      # )

      public_class_method def self.add_repeater_tab(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        name = opts[:name]
        raise 'ERROR: name parameter is required' if name.nil?

        request = opts[:request]
        raise 'ERROR: request parameter is required' if request.nil?

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        post_body = {
          name: name[0..29],
          request: request
        }.to_json

        repeater_resp = rest_browser.post(
          "http://#{mitm_rest_api}/repeater",
          post_body,
          content_type: 'application/json; charset=UTF8'
        )

        repeater_resp = JSON.parse(repeater_resp, symbolize_names: true)
        { id: repeater_resp[:value] }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # repeater_tabs = PWN::Plugins::BurpSuite.get_all_repeater_tabs(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.get_all_repeater_tabs(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        repeater_resp = rest_browser.get(
          "http://#{mitm_rest_api}/repeater",
          content_type: 'application/json; charset=UTF8'
        )

        JSON.parse(repeater_resp, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # repeater_tab = PWN::Plugins::BurpSuite.get_repeater_tab(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   id: 'required - id of the repeater tab to get'
      # )

      public_class_method def self.get_repeater_tab(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        id = opts[:id]
        raise 'ERROR: id parameter is required' if id.nil?

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        repeater_resp = rest_browser.get(
          "http://#{mitm_rest_api}/repeater/#{id}",
          content_type: 'application/json; charset=UTF8'
        )

        JSON.parse(repeater_resp, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # repeater_resp = PWN::Plugins::BurpSuite.send_repeater_request(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   id: 'required - id of the repeater tab to send'
      # )

      public_class_method def self.send_repeater_request(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        id = opts[:id]
        raise 'ERROR: id parameter is required' if id.nil?

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        repeater_resp = rest_browser.post(
          "http://#{mitm_rest_api}/repeater/#{id}/send",
          content_type: 'application/json; charset=UTF8'
        )

        JSON.parse(repeater_resp, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # repeater_obj = PWN::Plugins::BurpSuite.update_repeater_tab(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   id: 'required - id of the repeater tab to update',
      #   name: 'required - name of the repeater tab (max 30 characters)',
      #   request: 'required - base64 encoded HTTP request string'
      # )

      public_class_method def self.update_repeater_tab(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        id = opts[:id]
        raise 'ERROR: id parameter is required' if id.nil?

        name = opts[:name]
        raise 'ERROR: name parameter is required' if name.nil?

        request = opts[:request]
        raise 'ERROR: request parameter is required' if request.nil?

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        put_body = {
          name: name[0..29],
          request: request
        }.to_json

        repeater_resp = rest_browser.put(
          "http://#{mitm_rest_api}/repeater/#{id}",
          put_body,
          content_type: 'application/json; charset=UTF8'
        )

        JSON.parse(repeater_resp, symbolize_names: true)
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # uri_in_scope = PWN::Plugins::BurpSuite.delete_repeater_tab(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   id: 'required - id of the repeater tab to delete'
      # )

      public_class_method def self.delete_repeater_tab(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        id = opts[:id]
        raise 'ERROR: id parameter is required' if id.nil?

        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]

        rest_browser.delete(
          "http://#{mitm_rest_api}/repeater/#{id}",
          content_type: 'application/json; charset=UTF8'
        )

        { id: id }
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.generate_scan_report(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   target_url: 'required - target_url passed to #active_scan method',
      #   output_dir: 'required - directory to save the report',
      #   report_type: required - <:html|:xml>'
      # )

      public_class_method def self.generate_scan_report(opts = {})
        burp_obj = opts[:burp_obj]
        target_url = opts[:target_url]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        output_dir = opts[:output_dir]
        raise "ERROR: #{output_dir} does not exist." unless Dir.exist?(output_dir)

        report_type = opts[:report_type]

        valid_report_types_arr = %i[html xml]
        raise "ERROR: INVALID Report Type => #{report_type}" unless valid_report_types_arr.include?(report_type)

        case report_type
        when :html
          report_path = "#{output_dir}/burp_active_scan_results.html"
        when :xml
          report_path = "#{output_dir}/burp_active_scan_results.xml"
        end

        scheme = URI.parse(target_url).scheme
        host = URI.parse(target_url).host
        port = URI.parse(target_url).port
        path = URI.parse(target_url).path
        query = URI.parse(target_url).query

        target_domain = format_uri_from_sitemap_resp(
          scheme: scheme,
          host: host,
          port: port,
          path: path,
          query: query
        )

        puts "Generating #{report_type} report for #{target_domain}..."
        report_url = Base64.strict_encode64(target_domain)
        # Ready scanreport API call in pwn_burp to support HTML & XML report generation
        report_resp = rest_browser.get(
          "http://#{mitm_rest_api}/scanreport/#{report_type.to_s.upcase}/#{report_url}"
        )

        File.open(report_path, 'w') do |f|
          f.puts(report_resp.body.gsub("\r\n", "\n"))
        end
      rescue RestClient::BadRequest => e
        puts e.response
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.update_burp_jar(
      # )

      public_class_method def self.update_burp_jar
        # TODO: Do this if PortSwigger ever decides to includes this functionality as a CLI argument.
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.stop(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.stop(opts = {})
        burp_obj = opts[:burp_obj]

        browser_obj = burp_obj[:mitm_browser]
        rest_browser = burp_obj[:rest_browser]
        mitm_rest_api = burp_obj[:mitm_rest_api]
        introspection_thread = burp_obj[:introspection_thread]
        introspection_thread.kill unless introspection_thread.nil?

        PWN::Plugins::TransparentBrowser.close(browser_obj: browser_obj)
        rest_browser.post("http://#{mitm_rest_api}/shutdown", '')

        burp_obj = nil
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
          burp_obj1 = #{self}.start(
            burp_jar_path: 'optional - path of burp suite pro jar file (defaults to /opt/burpsuite/burpsuite_pro.jar)',
            headless: 'optional - run headless if set to true',
            browser_type: 'optional - defaults to :firefox. See PWN::Plugins::TransparentBrowser.help for a list of types'
          )

          uri_in_scope = #{self}.in_scope(
            burp_obj: 'required - burp_obj returned by #start method',
            uri: 'required - URI to determine if in scope'
          )

          json_in_scope = #{self}.add_to_scope(
            burp_obj: 'required - burp_obj returned by #start method',
            target_url: 'required - target url to add to scope'
          )

          json_spider = #{self}.spider(
            burp_obj: 'required - burp_obj returned by #start method',
            target_url: 'required - target url to spider in scope'
          )

          #{self}.enable_proxy(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          #{self}.disable_proxy(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          #{self}.get_proxy_listeners(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          json_proxy_listener = #{self}.add_proxy_listener(
            burp_obj: 'required - burp_obj returned by #start method',
            bindAddress: 'required - bind address for the proxy listener (e.g., \"127.0.0.1\")',
            port: 'required - port for the proxy listener (e.g., 8081)',
            enabled: 'optional - enable the listener (defaults to true)'
          )

          json_proxy_listener = #{self}.update_proxy_listener(
            burp_obj: 'required - burp_obj returned by #start method',
            id: 'optional - ID of the proxy listener (defaults to 0)',
            bindAddress: 'optional - bind address for the proxy listener (defaults to value of existing listener)',
            port: 'optional - port for the proxy listener (defaults to value of existing listener)',
            enabled: 'optional - enable the listener (defaults to value of existing listener)'
          )

          #{self}.delete_proxy_listener(
            burp_obj: 'required - burp_obj returned by #start method',
            id: 'optional - ID of the proxy listener (defaults to 0)'
          )

          json_proxy_history = #{self}.get_proxy_history(
            burp_obj: 'required - burp_obj returned by #start method',
            keyword: 'optional - keyword to filter proxy history results (default: nil)',
            return_as: 'optional - :base64 or :har (defaults to :base64)'
          )

          json_proxy_history = #{self}.update_proxy_history(
            burp_obj: 'required - burp_obj returned by #start method',
            entry: 'required - proxy history entry hash to update'
          )

          json_sitemap = #{self}.get_sitemap(
            burp_obj: 'required - burp_obj returned by #start method',
            keyword: 'optional - keyword to filter sitemap results (default: nil)',
            return_as: 'optional - :base64 or :har (defaults to :base64)'
          )

          json_sitemap = #{self}.add_to_sitemap(
            burp_obj: 'required - burp_obj returned by #start method',
            sitemap: 'required - sitemap hash to add',
            debug: 'optional - boolean to enable sitemap debugging (default: false)'
          )

          Example:
          json_sitemap = #{self}.add_to_sitemap(
            burp_obj: 'required - burp_obj returned by #start method',
            sitemap: {
              request: 'base64_encoded_request_string',
              response: 'base64_encoded_response_string',
              highlight: 'NONE'||'RED'||'ORANGE'||'YELLOW'||'GREEN'||'CYAN'||'BLUE'||'PINK'||'MAGENTA'||'GRAY',
              comment: 'optional comment for the sitemap entry',
              http_service: {
                host: 'example.com',
                port: 80,
                protocol: 'http'
              }
            }
          )

          json_sitemap = #{self}.update_sitemap(
            burp_obj: 'required - burp_obj returned by #start method',
            entry: 'required - sitemap entry hash to update'
          )

          json_sitemap = #{self}.import_openapi_to_sitemap(
            burp_obj: 'required - burp_obj returned by #start method',
            openapi_spec: 'required - path to OpenAPI JSON or YAML specification file',
            additional_http_headers: 'optional - hash of additional HTTP headers to include in requests (default: {})',
            debug: 'optional - boolean to enable debug logging (default: false)',
            highlight: 'optional - highlight color for the sitemap entry (default: \"NONE\")',
            comment: 'optional - comment for the sitemap entry (default: \"\")',
          )

          active_scan_url_arr = #{self}.active_scan(
            burp_obj: 'required - burp_obj returned by #start method',
            target_url: 'required - target url to scan in sitemap (should be loaded & authenticated w/ burp_obj[:mitm_browser])',
            exclude_paths: 'optional - array of paths to exclude from active scan (default: [])'
          )

          json_scan_issues = #{self}.get_scan_issues(
            burp_obj: 'required - burp_obj returned by #start method'
          ).to_json

          repeater_id = #{self}.add_repeater_tab(
            burp_obj: 'required - burp_obj returned by #start method',
            name: 'required - name of the repeater tab (max 30 characters)',
            request: 'optional - base64 encoded HTTP request string'
          )

          repeater_tabs = #{self}.get_all_repeater_tabs(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          repeater_tab = #{self}.get_repeater_tab(
            burp_obj: 'required - burp_obj returned by #start method',
            id: 'required - id of the repeater tab to get'
          )

          repeater_resp = #{self}.send_repeater_request(
            burp_obj: 'required - burp_obj returned by #start method',
            id: 'required - id of the repeater tab to send'
          )

          repeater_obj = #{self}.update_repeater_tab(
            burp_obj: 'required - burp_obj returned by #start method',
            id: 'required - id of the repeater tab to update',
            name: 'required - name of the repeater tab (max 30 characters)',
            request: 'required - base64 encoded HTTP request string'
          )

          repeater_obj = #{self}.delete_repeater_tab(
            burp_obj: 'required - burp_obj returned by #start method',
            id: 'required - id of the repeater tab to delete'
          )

          #{self}.generate_scan_report(
            burp_obj: 'required - burp_obj returned by #start method',
            target_url: 'required - target_url passed to #active_scan method',
            output_dir: 'required - directory to save the report',
            report_type: 'required - <:html|:xml>'
          )

          #{self}.stop(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          #{self}.authors
        "
      end
    end
  end
end
