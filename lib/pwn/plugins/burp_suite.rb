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
      # burp_obj = PWN::Plugins::BurpSuite.start(
      #   burp_jar_path: 'options - path of burp suite pro jar file (defaults to /opt/burpsuite/burpsuite_pro.jar)',
      #   headless: 'optional - run burp headless if set to true',
      #   browser_type: 'optional - defaults to :firefox. See PWN::Plugins::TransparentBrowser.help for a list of types',
      #   target_config: 'optional - path to burp suite pro target config JSON file'
      # )

      public_class_method def self.start(opts = {})
        burp_jar_path = opts[:burp_jar_path] ||= '/opt/burpsuite/burpsuite_pro.jar'
        raise 'Invalid path to burp jar file.  Please check your spelling and try again.' unless File.exist?(burp_jar_path)

        burp_root = File.dirname(burp_jar_path)

        browser_type = if opts[:browser_type].nil?
                         :firefox
                       else
                         opts[:browser_type]
                       end

        target_config = opts[:target_config]

        if opts[:headless]
          # burp_cmd_string = "java -Xmx4G -Djava.awt.headless=true -classpath #{burp_root}/burpbuddy.jar:#{burp_jar_path} burp.StartBurp"
          burp_cmd_string = "java -Xmx4G -Djava.awt.headless=true -classpath #{burp_root}/burpbuddy.jar -jar #{burp_jar_path}"
        else
          # burp_cmd_string = "java -Xmx4G -classpath #{burp_root}/burpbuddy.jar:#{burp_jar_path} burp.StartBurp"
          burp_cmd_string = "java -Xmx4G -classpath #{burp_root}/burpbuddy.jar -jar #{burp_jar_path}"
        end
        burp_cmd_string = "#{burp_cmd_string} --config-file=#{target_config}" if target_config && File.exist?(target_config)

        # Construct burp_obj
        burp_obj = {}
        burp_obj[:pid] = Process.spawn(burp_cmd_string)
        browser_obj1 = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
        rest_browser = browser_obj1[:browser]

        # random_mitm_port = PWN::Plugins::Sock.get_random_unused_port
        # random_bb_port = random_mitm_port
        # random_bb_port = PWN::Plugins::Sock.get_random_unused_port while random_bb_port == random_mitm_port
        burp_obj[:mitm_proxy] = '127.0.0.1:8080'
        burp_obj[:burpbuddy_api] = '127.0.0.1:8001'
        burp_obj[:rest_browser] = rest_browser

        # Proxy always listens on localhost...use SSH tunneling if remote access is required
        browser_obj2 = PWN::Plugins::TransparentBrowser.open(
          browser_type: browser_type,
          proxy: "http://#{burp_obj[:mitm_proxy]}"
        )

        burp_obj[:burp_browser] = browser_obj2

        # Wait for TCP 8001 to open prior to returning burp_obj
        loop do
          s = TCPSocket.new('127.0.0.1', 8001)
          s.close
          break
        rescue Errno::ECONNREFUSED
          print '.'
          sleep 3
          next
        end

        burp_obj
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # uri_in_scope_bool = PWN::Plugins::BurpSuite.uri_in_scope(
      #   target_config: 'required - path to burp suite pro target config JSON file',
      #   uri: 'required - URI to determine if in scope'
      # )

      public_class_method def self.uri_in_scope(opts = {})
        target_config = opts[:target_config]
        raise 'ERROR: target_config does not exist' unless File.exist?(target_config)

        uri = opts[:uri]
        raise 'ERROR: uri parameter is required' if uri.nil?

        target_config_json = JSON.parse(
          File.read(target_config),
          symbolize_names: true
        )

        out_of_scope = target_config_json[:target][:scope][:exclude]
        out_of_scope_arr = out_of_scope.select do |os|
          URI.parse(uri).scheme =~ /#{os[:protocol]}/ &&
            URI.parse(uri).host =~ /#{os[:host]}/ &&
            (URI.parse(uri).path =~ /#{os[:file]}/ || URI.parse(uri).path == '')
        end
        return false unless out_of_scope_arr.empty?

        in_scope = target_config_json[:target][:scope][:include]
        in_scope_arr = in_scope.select do |is|
          URI.parse(uri).scheme =~ /#{is[:protocol]}/ &&
            URI.parse(uri).host =~ /#{is[:host]}/ &&
            (URI.parse(uri).path =~ /#{is[:file]}/ || URI.parse(uri).path == '')
        end
        return false if in_scope_arr.empty?

        true
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::BurpSuite.enable_proxy(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.enable_proxy(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        burpbuddy_api = burp_obj[:burpbuddy_api]

        enable_resp = rest_browser.post("http://#{burpbuddy_api}/proxy/intercept/enable", nil)
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
        burpbuddy_api = burp_obj[:burpbuddy_api]

        disable_resp = rest_browser.post("http://#{burpbuddy_api}/proxy/intercept/disable", nil)
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_sitemap = PWN::Plugins::BurpSuite.get_current_sitemap(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.get_current_sitemap(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        burpbuddy_api = burp_obj[:burpbuddy_api]

        sitemap = rest_browser.get("http://#{burpbuddy_api}/sitemap", content_type: 'application/json; charset=UTF8')
        JSON.parse(sitemap)
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
        burpbuddy_api = burp_obj[:burpbuddy_api]
        target_url = opts[:target_url].to_s.scrub.strip.chomp
        target_scheme = URI.parse(target_url).scheme
        target_domain_name = URI.parse(target_url).host
        target_port = URI.parse(target_url).port.to_i
        if target_scheme == 'http'
          use_https = false
        else
          use_https = true
        end

        active_scan_url_arr = []
        json_sitemap = get_current_sitemap(burp_obj: burp_obj)
        json_sitemap.each do |site|
          json_http_svc = site['http_service']
          json_req = site['request']
          json_protocol = json_http_svc['protocol']
          json_host = json_http_svc['host'].to_s.scrub.strip.chomp
          json_port = json_http_svc['port'].to_i
          json_path = json_req['path']

          implicit_http_ports_arr = [
            80,
            443
          ]

          if implicit_http_ports_arr.include?(json_port)
            json_uri = "#{json_protocol}//#{json_host}#{json_path}"
          else
            json_uri = "#{json_protocol}//#{json_host}:#{json_port}#{json_path}"
          end

          next unless json_host == target_domain_name && json_port == target_port

          puts "Adding #{json_uri} to Active Scan"
          active_scan_url_arr.push(json_uri)
          # post_body = "{ \"host\": \"#{json_host}\", \"port\": \"#{json_port}\", \"useHttps\": #{use_https}, \"request\": \"#{json_req['raw']}\" }"
          post_body = "{ \"host\": \"#{json_host}\", \"port\": \"#{json_port}\", \"useHttps\": \"#{use_https}\", \"request\": \"#{json_req['raw']}\" }"
          # Kick off an active scan for each given page in the json_sitemap results
          rest_browser.post("http://#{burpbuddy_api}/scan/active", post_body, content_type: 'application/json')
        end

        # Wait for scan completion
        scan_queue = rest_browser.get("http://#{burpbuddy_api}/scan/active")
        json_scan_queue = JSON.parse(scan_queue)
        scan_queue_total = json_scan_queue.count
        json_scan_queue.each do |scan_item|
          this_scan_item_id = scan_item['id']
          until scan_item['status'] == 'finished'
            scan_item_resp = rest_browser.get("http://#{burpbuddy_api}/scan/active/#{this_scan_item_id}")
            scan_item = JSON.parse(scan_item_resp)
            scan_status = scan_item['status']
            puts "Target ID ##{this_scan_item_id} of ##{scan_queue_total}| #{scan_status}"
            sleep 3
          end
          puts "Target ID ##{this_scan_item_id} of ##{scan_queue_total}| 100% complete\n"
        end

        active_scan_url_arr # Return array of targeted URIs to pass to #generate_scan_report method
      rescue StandardError => e
        stop(burp_obj: burp_obj) unless burp_obj.nil?
        raise e
      end

      # Supported Method Parameters::
      # json_scan_issues = PWN::Plugins::BurpSuite.get_scan_issues(
      #   burp_obj: 'required - burp_obj returned by #start method'
      # )

      public_class_method def self.get_scan_issues(opts = {})
        burp_obj = opts[:burp_obj]
        rest_browser = burp_obj[:rest_browser]
        burpbuddy_api = burp_obj[:burpbuddy_api]

        scan_issues = rest_browser.get("http://#{burpbuddy_api}/scanissues")
        JSON.parse(scan_issues)
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
        burpbuddy_api = burp_obj[:burpbuddy_api]
        report_type = opts[:report_type]
        # When burpbuddy begins to support XML report generation
        valid_report_types_arr = %i[
          html
          xml
        ]

        raise 'INVALID Report Type' unless valid_report_types_arr.include?(report_type)

        output_path = opts[:output_path].to_s.scrub

        scheme = URI.parse(target_url).scheme
        host = URI.parse(target_url).host
        port = URI.parse(target_url).port

        implicit_http_ports_arr = [
          80,
          443
        ]

        if implicit_http_ports_arr.include?(port)
          target_domain = "#{scheme}://#{host}"
        else
          target_domain = "#{scheme}://#{host}:#{port}"
        end

        report_url = Base64.strict_encode64(target_domain)
        # Ready scanreport API call in burpbuddy to support HTML & XML report generation
        report_resp = rest_browser.get(
          "http://#{burpbuddy_api}/scanreport/#{report_type.to_s.upcase}/#{report_url}"
        )
        # report_resp = rest_browser.get(
        #   "http://#{burpbuddy_api}/scanreport/#{report_url}"
        # )
        File.open(output_path, 'w') do |f|
          f.puts(report_resp.body.gsub("\r\n", "\n"))
        end
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
          # PLEASE NOTE: IF RUNNING THIS MODULE THE FIRST TIME, YOU HAVE TO MANUALLY LOAD
          # /opt/burpsuite/burpsuite_pro.jar INTO THE BURP SUITE PRO UI IN ORDER FOR
          # THIS TO WORK PROPERLY MOVING FORWARD.  THIS SHOULD ONLY BE NECESSARY TO
          # DO ONCE.
          burp_obj = #{self}.start(
            burp_jar_path: 'required - path of burp suite pro jar file (defaults to /opt/burpsuite/burpsuite_pro.jar)',
            headless: 'optional - run headless if set to true',
            browser_type: 'optional - defaults to :firefox. See PWN::Plugins::TransparentBrowser.help for a list of types',
            target_config: 'optional - path to burp suite pro target config JSON file'
          )

          uri_in_scope_bool = #{self}.uri_in_scope(
            target_config: 'required - path to burp suite pro target config JSON file',
            uri: 'required - URI to determine if in scope'
          )

          #{self}.enable_proxy(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          #{self}.disable_proxy(
            burp_obj: 'required - burp_obj returned by #start method'
          )

          json_sitemap = #{self}.get_current_sitemap(
            burp_obj: 'required - burp_obj returned by #start method'
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
            active_scan_url_arr: 'required - active_scan_url_arr returned by #invoke_active_scan method',
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
