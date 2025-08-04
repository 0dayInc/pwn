# frozen_string_literal: true

require 'base64'
require 'json'
require 'socket'
require 'uri'

module PWN
  module Plugins
    # This plugin was created to interact w/ Burp Suite Pro in headless mode to kick off spidering/live scanning
    module BurpSuite
      # Supported Method Parameters::
      # uri = PWN::Plugins::BurpSuite.format_uri_from_sitemap_resp(
      #   scheme: 'required - scheme of the URI (http|https)',
      #   host: 'required - host of the URI',
      #   port: 'optional - port of the URI',
      #   path: 'optional - path of the URI'
      # )
      private_class_method def self.format_uri_from_sitemap_resp(opts = {})
        scheme = opts[:scheme]
        raise 'ERROR: scheme parameter is required' if scheme.nil?

        host = opts[:host]
        raise 'ERROR: host parameter is required' if host.nil?

        port = opts[:port]
        path = opts[:path]

        implicit_http_ports_arr = [
          80,
          443
        ]

        uri = "#{scheme}://#{host}:#{port}#{path}"
        uri = "#{scheme}://#{host}#{path}" if implicit_http_ports_arr.include?(port)

        uri
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # burp_obj = PWN::Plugins::BurpSuite.start(
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
        raise 'Invalid path to burp jar file.  Please check your spelling and try again.' unless File.exist?(burp_jar_path)

        raise 'ERROR: /opt/burpsuite/pwn-burp.jar not found.  For more details about installing this extension, checkout https://github.com/0dayinc/pwn_burp' unless File.exist?('/opt/burpsuite/pwn-burp.jar')

        burp_root = File.dirname(burp_jar_path)

        browser_type = opts[:browser_type] ||= :firefox
        burp_ip = opts[:burp_ip] ||= '127.0.0.1'
        burp_port = opts[:burp_port] ||= 8080
        # burp_port = opts[:burp_port] ||= PWN::Plugins::Sock.get_random_unused_port
        #
        pwn_burp_ip = opts[:pwn_burp_ip] ||= '127.0.0.1'
        pwn_burp_port = opts[:pwn_burp_port] ||= 1337
        # pwn_burp_port = opts[:pwn_burp_port] ||= PWN::Plugins::Sock.get_random_unused_port

        burp_cmd_string = 'java -Xmx4G'
        burp_cmd_string = "#{burp_cmd_string} -Djava.awt.headless=true" if opts[:headless]
        burp_cmd_string = "#{burp_cmd_string} -Dproxy.address=#{burp_ip} -Dproxy.port=#{burp_port}"
        burp_cmd_string = "#{burp_cmd_string} -Dserver.address=#{pwn_burp_ip} -Dserver.port=#{pwn_burp_port}"
        burp_cmd_string = "#{burp_cmd_string} -jar #{burp_jar_path}"

        # Construct burp_obj
        burp_obj = {}
        burp_obj[:pid] = Process.spawn(burp_cmd_string)
        browser_obj1 = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_browser = browser_obj1[:browser]

        burp_obj[:mitm_proxy] = "#{burp_ip}:#{burp_port}"
        burp_obj[:pwn_burp_api] = "#{pwn_burp_ip}:#{pwn_burp_port}"
        burp_obj[:rest_browser] = rest_browser

        # Proxy always listens on localhost...use SSH tunneling if remote access is required
        browser_obj2 = PWN::Plugins::TransparentBrowser.open(
          browser_type: browser_type,
          proxy: "http://#{burp_obj[:mitm_proxy]}",
          devtools: true
        )

        burp_obj[:burp_browser] = browser_obj2

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

        # USE THIS WHEN Updating Proxy Listener settings become
        # available in the BurpSuite Montoya API
        # Update proxy listener to use the burp_ip and burp_port
        # update_proxy_listener(
        #   burp_obj: burp_obj,
        #   address: burp_ip,
        #   port: burp_port
        # )

        burp_obj
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
        pwn_burp_api = burp_obj[:pwn_burp_api]
        base64_encoded_uri = Base64.strict_encode64(uri.to_s.scrub.strip.chomp)

        in_scope_resp = rest_browser.get(
          "http://#{pwn_burp_api}/scope/#{base64_encoded_uri}",
          content_type: 'application/json; charset=UTF8'
        )
        json_in_scope = JSON.parse(in_scope_resp, symbolize_names: true)
        json_in_scope[:value]
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
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
        pwn_burp_api = burp_obj[:pwn_burp_api]

        post_body = { url: target_url }.to_json

        in_scope = rest_browser.post("http://#{pwn_burp_api}/scope", post_body, content_type: 'application/json; charset=UTF8')
        JSON.parse(in_scope, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_in_scope = PWN::Plugins::BurpSuite.spider(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   target_url: 'required - target url to add to crawl / spider'
      # )

      public_class_method def self.spider(opts = {})
        burp_obj = opts[:burp_obj]
        target_url = opts[:target_url]
        rest_browser = burp_obj[:rest_browser]
        pwn_burp_api = burp_obj[:pwn_burp_api]

        post_body = { url: target_url }.to_json

        in_scope = rest_browser.post(
          "http://#{pwn_burp_api}/spider",
          post_body,
          content_type: 'application/json; charset=UTF8'
        )
        spider_json = JSON.parse(in_scope, symbolize_names: true)
        spider_id = spider_json[:id]

        spider_status_json = {}
        loop do
          print '.'
          spider_status_resp = rest_browser.get("http://#{pwn_burp_api}/spider/#{spider_id}")
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
        pwn_burp_api = burp_obj[:pwn_burp_api]

        enable_resp = rest_browser.post("http://#{pwn_burp_api}/proxy/intercept/enable", nil)
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
        pwn_burp_api = burp_obj[:pwn_burp_api]

        disable_resp = rest_browser.post("http://#{pwn_burp_api}/proxy/intercept/disable", nil)
        JSON.parse(disable_resp, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_sitemap = PWN::Plugins::BurpSuite.get_sitemap(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   target_url: 'optional - target URL to filter sitemap results (defaults to entire sitemap)'
      # )

      public_class_method def self.get_sitemap(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        pwn_burp_api = burp_obj[:pwn_burp_api]
        target_url = opts[:target_url]

        base64_encoded_target_url = Base64.strict_encode64(target_url.to_s.scrub.strip.chomp) if target_url

        rest_call = "http://#{pwn_burp_api}/sitemap"
        rest_call = "#{rest_call}/#{base64_encoded_target_url}" if target_url

        sitemap = rest_browser.get(
          rest_call,
          content_type: 'application/json; charset=UTF8'
        )

        JSON.parse(sitemap, symbolize_names: true)
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
        pwn_burp_api = burp_obj[:pwn_burp_api]
        sitemap = opts[:sitemap] ||= {}
        debug = opts[:debug] || false

        # Send POST request to /sitemap
        response = RestClient.post(
          "#{pwn_burp_api}/sitemap",
          sitemap.to_json,
          content_type: 'application/json; charset=UTF-8'
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
        raise StandardError, "HTTP error adding to sitemap: Status #{e.response.code}, Response: #{e.response.body}"
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters:
      # json_sitemap = PWN::Plugins::BurpSuite.import_openapi_to_sitemap(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   openapi_spec: 'required - path to OpenAPI JSON specification file',
      #   additional_http_headers: 'optional - hash of additional HTTP headers to include in requests (default: {})',
      #   highlight: 'optional - highlight color for the sitemap entry (default: "NONE")',
      #   comment: 'optional - comment for the sitemap entry (default: "")',
      #   debug: 'optional - boolean to enable debug logging (default: false)'
      # )
      public_class_method def self.import_openapi_to_sitemap(opts = {})
        burp_obj = opts[:burp_obj]
        raise 'ERROR: burp_obj parameter is required' unless burp_obj.is_a?(Hash)

        openapi_spec = opts[:openapi_spec]
        raise 'ERROR: openapi_spec parameter not found' unless File.exist?(openapi_spec)

        additional_http_headers = opts[:additional_http_headers] || {}
        raise 'ERROR: additional_http_headers must be a Hash' unless additional_http_headers.is_a?(Hash)

        highlight = opts[:highlight] ||= 'NONE'
        comment = opts[:comment].to_s.scrub

        debug = opts[:debug] || false

        # Parse the OpenAPI JSON
        openapi = JSON.parse(File.read(openapi_spec), symbolize_names: true)

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
                  # Combine path-level and operation-level parameters
                  operation_parameters = operation[:parameters].is_a?(Array) ? operation[:parameters] : []
                  all_parameters = path_parameters + operation_parameters
                  warn("[DEBUG] All parameters for #{method_str.upcase} #{full_path}: #{all_parameters.inspect}") if debug && !all_parameters.empty?

                  # Process path parameters for substitution
                  request_path = full_path.dup
                  query_params = []

                  all_parameters.each do |param|
                    next unless param.is_a?(Hash) && param[:name] && param[:in]

                    param_name = param[:name].to_s
                    case param[:in]
                    when 'path'
                      # Substitute path parameter with a default value (e.g., 'example')
                      param_value = param[:schema]&.dig(:example) || 'example'
                      request_path.gsub!("{#{param_name}}", param_value.to_s)
                    when 'query'
                      # Collect query parameters
                      param_value = param[:schema]&.dig(:example) || 'example'
                      query_params << "#{URI.encode_www_form_component(param_name)}=#{URI.encode_www_form_component(param_value.to_s)}"
                    end
                  end

                  # Append query parameters to path if any
                  request_path += "?#{query_params.join('&')}" if query_params.any?

                  # Construct HTTP request headers
                  request_headers = {
                    host: host
                  }
                  request_headers.merge!(additional_http_headers)

                  # Construct request lines, including all headers
                  request_lines = [
                    "#{method_str.upcase} #{request_path} HTTP/1.1"
                  ]
                  request_headers.each do |key, value|
                    # Capitalize header keys (e.g., 'host' to 'Host', 'authorization' to 'Authorization')
                    header_key = key.to_s.split('-').map(&:capitalize).join('-')
                    request_lines << "#{header_key}: #{value}"
                  end
                  request_lines << '' << '' # Add blank lines for HTTP request body separation

                  request = request_lines.join("\r\n")
                  encoded_request = Base64.strict_encode64(request)

                  # Determine response code from operation[:responses].keys
                  fallback_response_code = 200
                  response_keys = operation[:responses].keys
                  response_code = response_keys.find { |key| key.to_s.to_i.between?(100, 599) }.to_s.to_i
                  response_code ||= fallback_response_code

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

                  # Construct response body
                  response_body = operation[:responses][response_code]&.dig(:description) ||
                                  "Endpoint #{method_str.upcase} #{request_path} response"

                  # Safely determine Content-Type
                  content_type = if operation[:responses][response_code]
                                   content = operation[:responses][response_code][:content]
                                   content&.keys&.first || 'text/plain'
                                 else
                                   'text/plain'
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

        sitemap_arr.each { |sitemap| add_to_sitemap(burp_obj: burp_obj, sitemap: sitemap) }

        sitemap_arr
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # active_scan_url_arr = PWN::Plugins::BurpSuite.invoke_active_scan(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   target_url: 'required - target url to scan in sitemap (should be loaded & authenticated w/ burp_obj[:burp_browser])'
      # )

      public_class_method def self.invoke_active_scan(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        pwn_burp_api = burp_obj[:pwn_burp_api]
        target_url = opts[:target_url].to_s.scrub.strip.chomp
        target_scheme = URI.parse(target_url).scheme
        target_host = URI.parse(target_url).host
        target_port = URI.parse(target_url).port.to_i
        active_scan_url_arr = []

        json_sitemap = get_sitemap(burp_obj: burp_obj, target_url: target_url)
        json_sitemap.uniq.each do |site|
          # Skip if the site does not have a request or http_service
          puts "Site: #{site.inspect}"
          next if site[:request].empty?

          json_req = site[:request]
          b64_decoded_req = Base64.strict_decode64(json_req)
          json_path = b64_decoded_req.split[1].to_s.scrub.strip.chomp

          json_http_svc = site[:http_service]
          json_protocol = json_http_svc[:protocol]
          json_host = json_http_svc[:host].to_s.scrub.strip.chomp
          json_port = json_http_svc[:port].to_i

          json_uri = format_uri_from_sitemap_resp(
            scheme: json_protocol,
            host: json_host,
            port: json_port,
            path: json_path
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
            "http://#{pwn_burp_api}/scan/active",
            post_body,
            content_type: 'application/json'
          )
          puts " => #{resp.code}"
        rescue RestClient::ExceptionWithResponse => e
          puts " => #{e.response.code}"
          next
        end

        # Wait for scan completion
        scan_queue = rest_browser.get("http://#{pwn_burp_api}/scan/active")
        json_scan_queue = JSON.parse(scan_queue, symbolize_names: true)
        scan_queue_total = json_scan_queue.count
        json_scan_queue.each do |scan_item|
          this_scan_item_id = scan_item[:id]
          until scan_item[:status] == 'finished'
            scan_item_resp = rest_browser.get("http://#{pwn_burp_api}/scan/active/#{this_scan_item_id}")
            scan_item = JSON.parse(scan_item_resp, symbolize_names: true)
            scan_status = scan_item[:status]
            puts "Target ID ##{this_scan_item_id} of ##{scan_queue_total}| #{scan_status}"
            sleep 3
          end
          puts "Target ID ##{this_scan_item_id} of ##{scan_queue_total}| 100% complete\n"
        end

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
        pwn_burp_api = burp_obj[:pwn_burp_api]

        scan_issues = rest_browser.get("http://#{pwn_burp_api}/scanissues")
        JSON.parse(scan_issues, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.generate_scan_report(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   target_url: 'required - target_url passed to #invoke_active_scan method',
      #   report_type: :html|:xml|:both,
      #   output_path: 'required - path to save report results'
      # )

      public_class_method def self.generate_scan_report(opts = {})
        burp_obj = opts[:burp_obj]
        target_url = opts[:target_url]
        rest_browser = burp_obj[:rest_browser]
        pwn_burp_api = burp_obj[:pwn_burp_api]
        report_type = opts[:report_type]
        # When pwn_burp begins to support XML report generation
        valid_report_types_arr = %i[
          html
          xml
        ]

        raise 'INVALID Report Type' unless valid_report_types_arr.include?(report_type)

        output_path = opts[:output_path].to_s.scrub

        scheme = URI.parse(target_url).scheme
        host = URI.parse(target_url).host
        port = URI.parse(target_url).port
        path = URI.parse(target_url).path

        target_domain = format_uri_from_sitemap_resp(
          scheme: scheme,
          host: host,
          port: port,
          path: path
        )

        puts "Generating #{report_type} report for #{target_domain}..."
        report_url = Base64.strict_encode64(target_domain)
        # Ready scanreport API call in pwn_burp to support HTML & XML report generation
        report_resp = rest_browser.get(
          "http://#{pwn_burp_api}/scanreport/#{report_type.to_s.upcase}/#{report_url}"
        )

        File.open(output_path, 'w') do |f|
          f.puts(report_resp.body.gsub("\r\n", "\n"))
        end
      rescue RestClient::BadRequest => e
        puts e.response
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
        pwn_burp_api = burp_obj[:pwn_burp_api]

        listeners = rest_browser.get("http://#{pwn_burp_api}/proxy/listeners", content_type: 'application/json; charset=UTF8')
        JSON.parse(listeners, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_proxy_listener = PWN::Plugins::BurpSuite.add_proxy_listener(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   bind_address: 'required - bind address for the proxy listener (e.g., "127.0.0.1")',
      #   port: 'required - port for the proxy listener (e.g., 8081)',
      #   enabled: 'optional - enable the listener (defaults to true)'
      # )

      public_class_method def self.add_proxy_listener(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        pwn_burp_api = burp_obj[:pwn_burp_api]
        bind_address = opts[:bind_address]
        raise 'ERROR: bind_address parameter is required' if bind_address.nil?

        port = opts[:port]
        raise 'ERROR: port parameter is required' if port.nil?

        enabled = opts[:enabled] != false # Default to true if not specified

        post_body = {
          id: "#{bind_address}:#{port}",
          bind_address: bind_address,
          port: port,
          enabled: enabled
        }.to_json

        listener = rest_browser.post("http://#{pwn_burp_api}/proxy/listeners", post_body, content_type: 'application/json; charset=UTF8')
        JSON.parse(listener, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_proxy_listener = PWN::Plugins::BurpSuite.update_proxy_listener(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   id: 'optional - ID of the proxy listener (defaults to "127.0.0.1:8080")',
      #   bind_address: 'optional - bind address for the proxy listener (defaults to "127.0.0.1")',
      #   port: 'optional - port for the proxy listener (defaults to 8080)',
      #   enabled: 'optional - enable or disable the listener (defaults to true)'
      # )

      public_class_method def self.update_proxy_listener(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        pwn_burp_api = burp_obj[:pwn_burp_api]
        id = opts[:id] ||= '127.0.0.1:8080'
        bind_address = opts[:bind_address] ||= '127.0.0.1'
        port = opts[:port] ||= 8080
        enabled = opts[:enabled] != false # Default to true if not specified

        post_body = {
          id: id,
          bind_address: bind_address,
          port: port,
          enabled: enabled
        }.to_json

        listener = rest_browser.put("http://#{pwn_burp_api}/proxy/listeners/#{id}", post_body, content_type: 'application/json; charset=UTF8')
        JSON.parse(listener, symbolize_names: true)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.delete_proxy_listener(
      #   burp_obj: 'required - burp_obj returned by #start method',
      #   id: 'required - ID of the proxy listener (e.g., "127.0.0.1:8080")'
      # )

      public_class_method def self.delete_proxy_listener(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        pwn_burp_api = burp_obj[:pwn_burp_api]
        id = opts[:id]
        raise 'ERROR: id parameter is required' if id.nil?

        rest_browser.delete("http://#{pwn_burp_api}/proxy/listeners/#{id}")
        true # Return true to indicate successful deletion (or error if API fails)
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
        browser_obj = burp_obj[:burp_browser]
        burp_pid = burp_obj[:pid]

        browser_obj = PWN::Plugins::TransparentBrowser.close(browser_obj: browser_obj)
        Process.kill('TERM', burp_pid)

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
          burp_obj = #{self}.start(
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

          #{self}.enable_proxy(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          #{self}.disable_proxy(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          json_sitemap = #{self}.get_sitemap(
            burp_obj: 'required - burp_obj returned by #start method',
            target_url: 'optional - target URL to filter sitemap results (defaults to entire sitemap)'
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

          json_sitemap = #{self}.import_openapi_to_sitemap(
            burp_obj: 'required - burp_obj returned by #start method',
            openapi_spec: 'required - path to OpenAPI JSON specification file',
            additional_http_headers: 'optional - hash of additional HTTP headers to include in requests (default: {})',
            debug: 'optional - boolean to enable debug logging (default: false)',
            highlight: 'optional - highlight color for the sitemap entry (default: \"NONE\")',
            comment: 'optional - comment for the sitemap entry (default: \"\")',
          )

          active_scan_url_arr = #{self}.invoke_active_scan(
            burp_obj: 'required - burp_obj returned by #start method',
            target_url: 'required - target url to scan in sitemap (should be loaded & authenticated w/ burp_obj[:burp_browser])'
          )

          json_scan_issues = #{self}.get_scan_issues(
            burp_obj: 'required - burp_obj returned by #start method'
          ).to_json

          #{self}.generate_scan_report(
            burp_obj: 'required - burp_obj returned by #start method',
            target_url: 'required - target_url passed to #invoke_active_scan method',
            report_type: :html|:xml,
            output_path: 'required - path to save report results'
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
