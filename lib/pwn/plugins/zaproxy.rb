# frozen_string_literal: true

require 'cgi'
require 'fileutils'
require 'pty'
require 'securerandom'
require 'json'
require 'uri'

module PWN
  module Plugins
    # This plugin converts images to readable text
    # TODO: Convert all rest requests to POST instead of GET
    module Zaproxy
      @@logger = PWN::Plugins::PWNLogger.create

      # Supported Method Parameters::
      # zap_rest_call(
      #   zap_obj: 'required zap_obj returned from #start method',
      #   rest_call: 'required rest call to make per the schema',
      #   http_method: 'optional HTTP method (defaults to GET)
      #   http_body: 'optional HTTP body sent in HTTP methods that support it e.g. POST'
      # )

      private_class_method def self.zap_rest_call(opts = {})
        zap_obj = opts[:zap_obj]
        rest_call = opts[:rest_call].to_s.scrub
        http_method = opts[:http_method] ||= :get
        http_method = http_method.to_s.downcase.to_sym unless http_method.is_a?(Symbol)
        params = opts[:params]
        http_body = opts[:http_body].to_s.scrub

        rest_client = zap_obj[:rest_browser]::Request
        mitm_rest_api = zap_obj[:mitm_rest_api]

        base_zap_api_uri = "http://#{mitm_rest_api}"

        case http_method
        when :get
          response = rest_client.execute(
            method: :get,
            url: "#{base_zap_api_uri}/#{rest_call}",
            headers: {
              params: params
            },
            verify_ssl: false
          )

        when :post
          response = rest_client.execute(
            method: :post,
            url: "#{base_zap_api_uri}/#{rest_call}",
            headers: {
              content_type: 'application/json; charset=UTF-8'
            },
            payload: http_body,
            verify_ssl: false
          )

        else
          raise @@logger.error("Unsupported HTTP Method #{http_method} for #{self} Plugin")
        end

        sleep 3

        response
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # zap_obj = PWN::Plugins::Zaproxy.start(
      #   api_key: 'required - api key for API authorization',
      #   zap_bin_path: 'optional - path to zap.sh file'
      #   headless: 'optional - run zap headless if set to true',
      #   browser_type: 'optional - defaults to :firefox.  See PWN::Plugins::TransparentBrowser.help for a list of types',
      #   proxy: 'optional - change local zap proxy listener (defaults to http://127.0.0.1:<Random 1024-65535>)',
      # )

      public_class_method def self.start(opts = {})
        zap_obj = {}
        api_key = opts[:api_key]
        raise 'ERROR: api_key must be provided' if api_key.nil?

        zap_obj[:api_key] = api_key

        zap_bin_path = opts[:zap_bin_path] ||= '/usr/share/zaproxy/zap.sh'
        raise "ERROR: #{zap_bin_path} not found." unless File.exist?(zap_bin_path)

        zap_bin = File.basename(zap_bin_path)
        zap_root = File.dirname(zap_bin_path)

        headless = opts[:headless] || false
        browser_type = opts[:browser_type] ||= :firefox
        browser_type = browser_type.to_s.downcase.to_sym unless browser_type.is_a?(Symbol)
        browser_type = :headless if headless
        zap_ip = opts[:zap_ip] ||= '127.0.0.1'
        zap_port = opts[:zap_port] ||= PWN::Plugins::Sock.get_random_unused_port

        zap_rest_ip = zap_ip
        zap_rest_port = zap_port

        browser_obj1 = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_browser = browser_obj1[:browser]

        zap_obj[:mitm_proxy] = "#{zap_ip}:#{zap_port}"
        zap_obj[:mitm_rest_api] = zap_obj[:mitm_proxy]
        zap_obj[:rest_browser] = rest_browser

        browser_obj2 = PWN::Plugins::TransparentBrowser.open(
          browser_type: browser_type,
          proxy: "http://#{zap_obj[:mitm_proxy]}",
          devtools: true
        )

        zap_obj[:mitm_browser] = browser_obj2

        timestamp = Time.now.strftime('%Y-%m-%d_%H-%M-%S%z')
        session_path = "/tmp/zaproxy-#{timestamp}.session"
        zap_obj[:session_path] = session_path

        if headless
          # TODO: Ensure Default Context still exists and is default context
          zaproxy_cmd = "cd #{zap_root} && ./#{zap_bin} -daemon -newsession #{session_path}"
        else
          zaproxy_cmd = "cd #{zap_root} && ./#{zap_bin} -newsession #{session_path}"
        end

        zaproxy_cmd = "#{zaproxy_cmd} -host #{zap_ip} -port #{zap_port}"

        zap_obj[:pid] = Process.spawn(zaproxy_cmd)
        # Wait for pwn_burp_port to open prior to returning burp_obj
        loop do
          s = TCPSocket.new(zap_rest_ip, zap_rest_port)
          s.close
          break
        rescue Errno::ECONNREFUSED
          print '.'
          sleep 3
          next
        end

        zap_obj
      rescue Selenium::WebDriver::Error::SessionNotCreatedError, StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.import_openapi_to_sitemap(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   openapi_spec: 'required - path to OpenAPI JSON or YAML spec file',
      #   additional_http_headers: 'optional - hash of additional HTTP headers to include in requests (default: {})',
      #   target_regex: 'optional - url regex to inject additional_http_headers into (e.g. https://test.domain.local.*)'
      # )

      public_class_method def self.import_openapi_to_sitemap(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        openapi_spec = opts[:openapi_spec]
        raise "ERROR: openapi_spec file #{openapi_spec} does not exist" unless File.exist?(openapi_spec)

        openapi_spec_root = File.dirname(openapi_spec)
        Dir.chdir(openapi_spec_root)

        additional_http_headers = opts[:additional_http_headers] ||= {}
        raise 'ERROR: additional_http_headers must be a Hash' unless additional_http_headers.is_a?(Hash)

        target_regex = opts[:target_regex]

        if additional_http_headers.any?
          inject_additional_http_headers(
            zap_obj: zap_obj,
            target_regex: target_regex,
            headers: additional_http_headers
          )
        end

        params = {
          apikey: api_key,
          file: openapi_spec
        }

        response = zap_rest_call(
          zap_obj: zap_obj,
          rest_call: 'JSON/openapi/action/importFile/',
          params: params
        )

        JSON.parse(response.body, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_sitemap = PWN::Plugins::Zaproxy.get_sitemap(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   keyword: 'optional - string to search for in the sitemap entries (defaults to nil)',
      #   return_as: 'optional - :base64 or :har (defaults to :base64)'
      # )

      public_class_method def self.get_sitemap(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        keyword = opts[:keyword]
        return_as = opts[:return_as] ||= :base64
        raise 'ERROR: return_as must be :base64 or :har' unless %i[base64 har].include?(return_as)

        entries = []
        start = 0
        count = 1000

        # Get all entries in sitemap
        loop do
          params = { apikey: api_key, start: start, count: count }

          response = zap_rest_call(
            zap_obj: zap_obj,
            rest_call: 'OTHER/exim/other/exportHar/',
            params: params
          )

          har_data = JSON.parse(response.body, symbolize_names: true)
          new_entries = har_data[:log][:entries]
          break if new_entries.empty?

          entries += new_entries
          start += count
        end

        if keyword
          entries = har_sitemap.select do |site|
            json_request = site[:request].to_json
            json_request.include?(keyword)
          end
        end

        if return_as == :base64
          # Deduplicate entries based on method + url
          base64_entries = []
          entries.each do |entry|
            entry_hash = {}
            req = entry[:request]
            key = [req[:method], req[:url]]

            # Build full request string
            req_line = "#{req[:method]} #{req[:url]} #{req[:httpVersion]}\r\n"
            req_headers = req[:headers].map { |h| "#{h[:name]}: #{h[:value]}\r\n" }.join
            req_body = ''
            if req[:postData] && req[:postData][:text]
              req_body = req[:postData][:text]
              req_body = Base64.decode64(req_body) if req[:postData][:encoding] == 'base64'
            end
            full_req = "#{req_line}#{req_headers}\r\n#{req_body}".force_encoding('ASCII-8BIT')
            encoded_req = Base64.strict_encode64(full_req)

            # Build full response string
            res = entry[:response]
            res_line = "#{res[:httpVersion]} #{res[:status]} #{res[:statusText]}\r\n"
            res_headers = res[:headers].map { |h| "#{h[:name]}: #{h[:value]}\r\n" }.join
            res_body = ''
            if res[:content] && res[:content][:text]
              res_body = res[:content][:text]
              res_body = Base64.decode64(res_body) if res[:content][:encoding] == 'base64'
            end
            full_res = "#{res_line}#{res_headers}\r\n#{res_body}".force_encoding('ASCII-8BIT')
            encoded_res = Base64.strict_encode64(full_res)

            # Extract http_service
            uri = URI.parse(req[:url])
            http_service = {
              host: uri.host,
              port: uri.port,
              protocol: uri.scheme
            }

            # Add to array
            entry_hash[:request] = encoded_req
            entry_hash[:response] = encoded_res
            entry_hash[:http_service] = http_service
            base64_entries.push(entry_hash)
          end
          entries = base64_entries
        end

        entries.uniq
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.add_to_scope(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   target_regex: 'required - url regex to add to scope (e.g. https://test.domain.local.*)',
      #   context_name: 'optional - context name to add target_regex to (defaults to Default Context)'
      # )

      public_class_method def self.add_to_scope(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        target_regex = opts[:target_regex]
        raise 'ERROR: target_url must be provided' if target_regex.nil?

        context_name = opts[:context_name] ||= 'Default Context'

        params = {
          apikey: api_key,
          contextName: context_name,
          regex: target_regex
        }

        response = zap_rest_call(
          zap_obj: zap_obj,
          rest_call: 'JSON/context/action/includeInContext/',
          params: params
        )

        JSON.parse(response.body, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.requester(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   har_entry: 'required - har entry (e.g. from #get_sitemap method method)',
      #   redirect: 'optional - follow redirects if set to true (defaults to false)'
      # )

      public_class_method def self.requester(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        har_entry = opts[:har_entry]
        raise 'ERROR: har_entry must be provided and be a valid HAR entry' unless har_entry.is_a?(Hash) && har_entry.key?(:request) && har_entry.key?(:response)

        redirect = opts[:redirect] || false
        raise 'ERROR: redirect must be a boolean' unless redirect.is_a?(TrueClass) || redirect.is_a?(FalseClass)

        har_json = har_entry.to_json
        params = {
          apikey: api_key,
          request: har_json,
          followRedirects: redirect.to_s
        }

        response = zap_rest_call(
          zap_obj: zap_obj,
          rest_call: 'OTHER/exim/other/sendHarRequest/',
          params: params
        )

        JSON.parse(response.body, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.spider(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   target_url: 'required - url to spider'
      # )

      public_class_method def self.spider(opts = {})
        zap_obj = opts[:zap_obj]
        target_url = opts[:target_url].to_s.scrub
        api_key = zap_obj[:api_key].to_s.scrub

        # target_domain_name = URI.parse(target_url).host

        params = {
          apikey: api_key,
          url: target_url,
          maxChildren: 9,
          recurse: 3,
          contextName: '',
          subtreeOnly: target_url
        }

        response = zap_rest_call(
          zap_obj: zap_obj,
          rest_call: 'JSON/spider/action/scan/',
          params: params
        )

        spider = JSON.parse(response.body, symbolize_names: true)
        spider_id = spider[:scan].to_i

        loop do
          params = {
            apikey: api_key,
            scanId: spider_id
          }

          response = zap_rest_call(
            zap_obj: zap_obj,
            rest_call: 'JSON/spider/view/status/',
            params: params
          )

          spider = JSON.parse(response.body, symbolize_names: true)
          status = spider[:status].to_i
          puts "Spider ID: #{spider_id} => #{status}% Complete"
          break if status == 100
        end
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.inject_additional_http_headers(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   target_regex: 'required - url regex to inject headers into (e.g. https://test.domain.local.*)',
      #   headers: 'required - hash of additional headers to inject into each request',
      # )

      public_class_method def self.inject_additional_http_headers(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        target_regex = opts[:target_regex]
        raise 'ERROR: target_regex must be provided' if target_regex.nil?

        headers = opts[:headers] ||= {}
        raise 'ERROR: headers must be provided' if headers.empty? || !headers.is_a?(Hash)

        # Check if replacer rule already exists
        params = { apikey: api_key }
        response = zap_rest_call(
          zap_obj: zap_obj,
          rest_call: 'JSON/replacer/view/rules/',
          params: params
        )
        replacer = JSON.parse(response.body, symbolize_names: true)

        replacer_resp_arr = []
        headers.each_key do |header_key|
          this_header = { header: header_key }
          rule_exists = replacer[:rules].any? { |rule| rule[:description] == header_key.to_s && rule[:url] == target_regex }

          if rule_exists
            # Remove existing rule first
            puts "Removing existing replacer rule for header key: #{header_key}..."
            params = {
              apikey: api_key,
              description: header_key
            }
            zap_rest_call(
              zap_obj: zap_obj,
              rest_call: 'JSON/replacer/action/removeRule/',
              params: params
            )
          end

          puts "Adding replacer rule for header key: #{header_key}..."
          params = {
            apikey: api_key,
            description: header_key,
            enabled: 'true',
            matchType: 'REQ_HEADER',
            matchRegex: 'false',
            matchString: header_key,
            replacement: headers[header_key],
            initiators: '',
            url: target_regex
          }

          response = zap_rest_call(
            zap_obj: zap_obj,
            rest_call: 'JSON/replacer/action/addRule/',
            params: params
          )

          json_resp = JSON.parse(response.body, symbolize_names: true)
          this_header[:Result] = json_resp[:Result]
          replacer_resp_arr.push(this_header)
        end

        replacer_resp_arr
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.active_scan(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   target_url:  'required - url to scan',
      #   exclude_paths: 'optional - array of paths to exclude from scan (default: [])',
      #   scan_policy: 'optional - scan policy to use (defaults to Default Policy)'
      # )

      public_class_method def self.active_scan(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        target_url = opts[:target_url]
        raise 'ERROR: target_url must be provided' if target_url.nil?

        exclude_paths = opts[:exclude_paths] ||= []
        scan_policy = opts[:scan_policy] ||= 'Default Policy'

        exclude_paths.each do |exclude_path|
          # Remove trailing .* from target_url if it exists
          target_url = target_url.delete_suffix('.*') if target_url.end_with?('.*')
          exclude_path_regex = "#{target_url}#{exclude_path}.*"
          params = {
            apikey: api_key,
            regex: exclude_path_regex
          }
          zap_rest_call(
            zap_obj: zap_obj,
            rest_call: 'JSON/ascan/action/excludeFromScan/',
            params: params
          )
          puts "Excluding #{exclude_path_regex} from Active Scan"
        end

        # TODO: Implement adding target_url to scope so that inScopeOnly can be changed to true
        params = {
          apikey: api_key,
          url: target_url,
          recurse: true,
          inScopeOnly: true,
          scanPolicyName: scan_policy
        }

        response = zap_rest_call(
          zap_obj: zap_obj,
          rest_call: 'JSON/ascan/action/scan/',
          params: params
        )

        active_scan = JSON.parse(response.body, symbolize_names: true)
        active_scan_id = active_scan[:scan].to_i

        loop do
          params = {
            apikey: api_key,
            scanId: active_scan_id
          }

          response = zap_rest_call(
            zap_obj: zap_obj,
            rest_call: 'JSON/ascan/view/status/',
            params: params
          )

          active_scan = JSON.parse(response.body, symbolize_names: true)
          status = active_scan[:status].to_i
          puts "Active Scan ID: #{active_scan_id} => #{status}% Complete"
          break if status == 100
        end
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.get_alerts(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   target_url: 'required - base url to return alerts'
      # )

      public_class_method def self.get_alerts(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        target_url = opts[:target_url]

        params = {
          apikey: api_key,
          url: target_url
        }

        response = zap_rest_call(
          zap_obj: zap_obj,
          rest_call: 'JSON/core/view/alerts/',
          params: params
        )

        JSON.parse(response.body, symbolize_names: true)
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # report_path = PWN::Plugins::Zaproxy.generate_scan_report(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   output_dir: 'required - directory to save report',
      #   report_type: 'required - <:html|:markdown|:xml>'
      # )

      public_class_method def self.generate_scan_report(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        output_dir = opts[:output_dir]
        raise "ERROR: output_dir #{output_dir} does not exist." unless Dir.exist?(output_dir)

        report_type = opts[:report_type]

        valid_report_types_arr = %i[html markdown xml]
        raise "ERROR: Invalid report_type => #{report_type}" unless valid_report_types_arr.include?(report_type)

        case report_type
        when :html
          report_path = "#{output_dir}/zaproxy_active_scan_results.html"
          rest_call = 'OTHER/core/other/htmlreport/'
        when :markdown
          report_path = "#{output_dir}/zaproxy_active_scan_results.md"
          rest_call = 'OTHER/core/other/mdreport/'
        when :xml
          report_path = "#{output_dir}/zaproxy_active_scan_results.xml"
          rest_call = 'OTHER/core/other/xmlreport/'
        end

        params = {
          apikey: api_key
        }

        response = zap_rest_call(
          zap_obj: zap_obj,
          rest_call: rest_call,
          params: params
        )

        File.open(report_path, 'w') do |f|
          f.puts response.body
        end

        report_path
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.breakpoint(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   regex_type: 'required - :url, :request_header, :request_body, :response_header or :response_body',
      #   regex_pattern: 'required - regex pattern to search for respective regex_type',
      #   enabled: 'optional - boolean (defaults to true)'
      # )

      public_class_method def self.breakpoint(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub

        case opts[:regex_type].to_sym
        when :url, :request_header, :request_body, :response_header, :response_body
          regex_type = opts[:regex_type].to_sym
        else
          raise "Unknown regex_type: #{opts[:regex_type].to_sym}\noptions are :url, :request_header, :request_body, :response_header or :response_body"
        end
        regex_pattern = opts[:regex_pattern]
        enabled = opts[:enabled]

        enabled = true if enabled.nil?
        enabled ? (action = 'addHttpBreakpoint') : (action = 'removeHttpBreakpoint')

        zap_rest_call(
          zap_obj: zap_obj,
          rest_call: "JSON/break/action/#{action}/?zapapiformat=JSON&apikey=#{api_key}&string=#{regex_pattern}&location=#{regex_type}&match=regex&inverse=false&ignorecase=true",
          http_method: :get
        )
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.tamper(
      #   zap_obj: 'required - zap_obj returned from #open method',
      #   domain: 'required - FQDN to tamper (e.g. test.domain.local)',
      #   enabled: 'optional - boolean (defaults to true)'
      # )

      public_class_method def self.tamper(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key].to_s.scrub
        domain = opts[:domain]
        enabled = opts[:enabled]

        enabled = true if enabled.nil?
        enabled ? (action = 'addHttpBreakpoint') : (action = 'removeHttpBreakpoint')

        zap_rest_call(
          zap_obj: zap_obj,
          rest_call: "JSON/break/action/#{action}/?zapapiformat=JSON&apikey=#{api_key}&string=#{domain}&location=url&match=contains&inverse=false&ignorecase=true",
          http_method: :get
        )

        zap_rest_call(
          zap_obj: zap_obj,
          rest_call: "JSON/break/action/break/?zapapiformat=JSON&apikey=#{api_key}&type=http-request&state=#{enabled}",
          http_method: :get
        )
      rescue StandardError, SystemExit, Interrupt => e
        stop(zap_obj: zap_obj) unless zap_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::Zaproxy.stop(
      #   zap_obj: 'required - zap_obj returned from #open method'
      # )

      public_class_method def self.stop(opts = {})
        zap_obj = opts[:zap_obj]
        api_key = zap_obj[:api_key]
        browser_obj = zap_obj[:mitm_browser]

        PWN::Plugins::TransparentBrowser.close(browser_obj: browser_obj)

        params = { apikey: api_key }
        zap_rest_call(
          zap_obj: zap_obj,
          rest_call: 'JSON/core/action/shutdown/',
          params: params
        )

        session_path = zap_obj[:session_path]
        session_path_files = Dir.glob("#{session_path}*")
        # Remove session files - need to add a slight delay between each unlink to work around file locks
        session_path_files.each do |f|
          FileUtils.rm_f(f)
          sleep 0.3
        end

        zap_obj = nil
      rescue StandardError, SystemExit, Interrupt => e
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
          zap_obj = #{self}.start(
            api_key: 'required - api key for API authorization',
            zap_bin_path: 'optional - path to zap.sh file',
            headless: 'optional - run zap headless if set to true',
            proxy: 'optional - change local zap proxy listener (defaults to http://127.0.0.1:<Random 1024-65535>)'
          )

          #{self}.spider(
            zap_obj: 'required - zap_obj returned from #open method',
            target_url: 'required - url to spider'
          )

          #{self}.import_openapi_to_sitemap(
            zap_obj: 'required - zap_obj returned from #open method',
            openapi_spec: 'required - path to OpenAPI JSON or YAML spec file',
            additional_http_headers: 'optional - hash of additional HTTP headers to include in requests (default: {})',
            target_regex: 'optional - url regex to inject additional_http_headers into (e.g. https://test.domain.local.*)'
          )

          #{self}.get_sitemap(
            zap_obj: 'required - zap_obj returned from #open method',
            keyword: 'optional - string to search for in the sitemap entries (defaults to nil)',
            return_as: 'optional - :base64 or :har (defaults to :base64)'
          )

          #{self}.add_to_scope(
            zap_obj: 'required - zap_obj returned from #open method',
            target_regex: 'required - url regex to add to scope (e.g. https://test.domain.local.*)',
            context_name: 'optional - context name to add target_regex to (defaults to Default Context)'
          )

          #{self}.requester(
            zap_obj: 'required - zap_obj returned from #open method',
            har_entry: 'required - har entry (e.g. from #get_sitemap method method)',
            redirect: 'optional - follow redirects if set to true (defaults to true)'
          )

          json_sitemap = #{self}.spider(
            zap_obj: 'required - zap_obj returned from #open method'
          )

          #{self}.inject_additional_http_headers(
            zap_obj: 'required - zap_obj returned from #open method',
            target_regex: 'required - url regex to inject headers into (e.g. https://test.domain.local.*)',
            headers: 'required - hash of additional headers to inject into each request'
          )

          #{self}.active_scan(
            zap_obj: 'required - zap_obj returned from #open method'
            target_url: 'required - url to scan',
            exclude_paths: 'optional - array of paths to exclude from scan (default: [])',
            scan_policy: 'optional - scan policy to use (defaults to Default Policy)'
          )

          json_alerts = #{self}.get_alerts(
            zap_obj: 'required - zap_obj returned from #open method'
            target_url: 'required - base url to return alerts'
          )

          report_path = #{self}.generate_scan_report(
            zap_obj: 'required - zap_obj returned from #open method',
            output_dir: 'required - directory to save report',
            report_type: 'required - <:html|:markdown|:xml>'
          )

          #{self}.breakpoint(
            zap_obj: 'required - zap_obj returned from #open method',
            regex_type: 'required - :url, :request_header, :request_body, :response_header or :response_body',
            regex_pattern: 'required - regex pattern to search for respective regex_type',
            enabled: 'optional - boolean (defaults to true)'
          )

          #{self}.tamper(
            zap_obj: 'required - zap_obj returned from #open method',
            domain: 'required - FQDN to tamper (e.g. test.domain.local)',
            enabled: 'optional - boolean (defaults to true)'
          )

          #{self}.stop(
            zap_obj: 'required - zap_obj returned from #start method'
          )

          #{self}.authors
        "
      end
    end
  end
end
