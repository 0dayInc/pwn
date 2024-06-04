# frozen_string_literal: true

require 'ipaddress'
require 'json'
require 'openssl'
require 'resolv'

module PWN
  module Plugins
    # This plugin leverages ip-api.com's REST API to discover information about IP addresses
    # 1,000 daily requests are allowed for free
    module IPInfo
      # Supported Method Parameters::
      # ip_resp_hash = ip_info_rest_call(
      #   ip: 'required - IP or Host to lookup',
      #   proxy: 'optional - use a proxy'
      # )

      private_class_method def self.ip_info_rest_call(opts = {})
        ip = opts[:ip].to_s.scrub.strip.chomp
        proxy = opts[:proxy]

        if IPAddress.valid?(ip)
          if proxy
            browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest, proxy: proxy)
          else
            browser_obj = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
          end
          rest_client = browser_obj[:browser]

          ip_resp_str = rest_client.get("http://ip-api.com/json/#{ip}?fields=country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse,mobile,proxy,query,status,message")
          ip_resp_hash = JSON.parse(
            ip_resp_str,
            symbolize_names: true
          )

          # Ensure the max number of IPs we can query / min = 120 to avoid being banned
          # Per http://ip-api.com/docs/api:json:
          # "Our system will automatically ban any IP address doing over 150 requests per minute"
          # To unban a banned IP, visit http://ip-api.com/docs/unban
          sleep 0.5

          ip_resp_hash
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # ip_info_struc = PWN::Plugins::IPInfo.get(
      #   target: 'required - IP or Host to lookup',
      #   proxy: 'optional - use a proxy',
      #   tls_port: 'optional port to check cert for Domain Name (default: 443). Will not execute if proxy parameter is set.',
      #   skip_api: 'optional - skip the API call'
      # )

      public_class_method def self.get(opts = {})
        target = opts[:target].to_s.scrub.strip.chomp.downcase
        proxy = opts[:proxy]
        tls_port = opts[:tls_port] ||= 443
        skip_api = opts[:skip_api] ||= false

        ip_info_resp = []
        ip_resp_hash = {}
        is_ip = IPAddress.valid?(target)

        begin
          ip_resp_hash[:hostname] = target
          target = Resolv.getaddress(target) unless is_ip
        rescue Resolv::ResolvError
          target = nil
        end

        ip_resp_hash = ip_info_rest_call(ip: target, proxy: proxy) unless skip_api
        ip_resp_hash[:ip] = target
        ip_info_resp.push(ip_resp_hash) unless target.nil?

        if proxy.nil? && is_ip
          ip_info_resp.each do |ip_resp|
            tls_port_avail = PWN::Plugins::Sock.check_port_in_use(
              server_ip: target,
              port: tls_port
            )

            ip_resp[:tls_avail] = tls_port_avail
            ip_resp[:ca_issuer_uris] = nil
            ip_resp[:cert_subject] = nil
            ip_resp[:cert_issuer] = nil
            ip_resp[:cert_serial] = nil
            ip_resp[:crl_uris] = nil
            ip_resp[:extensions] = nil
            ip_resp[:not_before] = nil
            ip_resp[:not_after] = nil
            ip_resp[:oscsp_uris] = nil
            ip_resp[:pem] = nil
            ip_resp[:signature_algorithm] = nil
            ip_resp[:version] = nil
            next unless tls_port_avail

            cert_obj = PWN::Plugins::Sock.get_tls_cert(
              target: target,
              port: tls_port
            )

            next unless cert_obj.is_a?(OpenSSL::X509::Certificate)

            ip_resp[:ca_issuer_uris] = cert_obj.ca_issuer_uris.map(&:to_s) unless cert_obj.ca_issuer_uris.nil?
            ip_resp[:cert_subject] = cert_obj.subject.to_s
            ip_resp[:cert_issuer] = cert_obj.issuer.to_s
            ip_resp[:cert_serial] = cert_obj.serial.to_s
            ip_resp[:crl_uris] = cert_obj.crl_uris.map(&:to_s) unless cert_obj.crl_uris.nil?
            ip_resp[:extensions] = cert_obj.extensions.to_h { |ext| [ext.oid.to_s.to_sym, ext.value] } unless cert_obj.extensions.nil?
            ip_resp[:not_before] = cert_obj.not_before.to_s
            ip_resp[:not_after] = cert_obj.not_after.to_s
            ip_resp[:oscsp_uris] = cert_obj.ocsp_uris.map(&:to_s) unless cert_obj.ocsp_uris.nil?
            ip_resp[:pem] = cert_obj.to_pem.to_s
            ip_resp[:signature_algorithm] = cert_obj.signature_algorithm.to_s
            ip_resp[:version] = cert_obj.version.to_s
          end
        end

        ip_info_resp
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # PWN::Plugins::IPInfo.bruteforce_subdomains(
      #   parent_domain: 'required - Parent Domain to brute force',
      #   dictionary: 'required - Dictionary to use for subdomain brute force',
      #   max_threads: 'optional - Maximum number of threads to use (default: 9)',
      #   proxy: 'optional - use a proxy',
      #   tls_port: 'optional port to check cert for Domain Name (default: 443). Will not execute if proxy parameter is set.',
      #   results_file: 'optional - File to write results to (default: /tmp/parent_domain-timestamp-pwn_bruteforce_subdomains.txt)'
      # )
      public_class_method def self.bruteforce_subdomains(opts = {})
        parent_domain = opts[:parent_domain].to_s.scrub.strip.chomp
        raise 'ERROR: parent_domain parameter is required' if parent_domain.empty?

        default_dictionary = '/usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt'
        dictionary = opts[:dictionary] ||= default_dictionary
        raise "ERROR: Dictionary file not found: #{dictionary}" unless File.exist?(dictionary)

        max_threads = opts[:max_threads]

        proxy = opts[:proxy]
        tls_port = opts[:tls_port]
        timestamp = Time.now.strftime('%Y-%m-%d_%H.%M.%S')
        results_file = opts[:results_file] ||= "/tmp/SUBS.#{parent_domain}-#{timestamp}-pwn_bruteforce_subdomains.txt"

        File.write(results_file, "[\n")

        # Break up dictonary file into sublines and process each subline in a thread
        dict_lines = File.readlines(dictionary).shuffle
        mutex = Mutex.new
        PWN::Plugins::ThreadPool.fill(
          enumerable_array: dict_lines,
          max_threads: max_threads
        ) do |subline|
          print '.'
          subdomain = subline.to_s.scrub.strip.chomp
          target = parent_domain if subdomain.empty?
          target = "#{subdomain}.#{parent_domain}" unless subdomain.empty?
          ip_info_resp = get(
            target: target,
            proxy: proxy,
            tls_port: tls_port,
            skip_api: true
          )

          mutex.synchronize do
            File.open(results_file, 'a') do |file|
              resp_len = ip_info_resp.length
              next unless resp_len.positive?

              ip_info_resp.each do |ip_info_hash|
                file.puts "#{JSON.generate(ip_info_hash)},"
              end
            end
          end
        end
      rescue StandardError => e
        raise e
      ensure
        # Strip trailing comma and close JSON array
        final_results = File.readlines(results_file)
        # Strip trailing comma from last line
        last_line = final_results[-1][0..-2]
        final_results[-1] = last_line
        File.write(results_file, "#{final_results.join}\n]")
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
          ip_info_struc = #{self}.get(
            target: 'required - IP or Host to lookup',
            proxy: 'optional - use a proxy',
            tls_port: 'optional port to check cert for Domain Name (default: 443). Will not execute if proxy parameter is set.',
            skip_api: 'optional - skip the API call'
          )

          #{self}.bruteforce_subdomains(
            parent_domain: 'required - Parent Domain to brute force',
            dictionary: 'required - Dictionary to use for subdomain brute force',
            max_threads: 'optional - Maximum number of threads to use (default: 9)',
            proxy: 'optional - use a proxy',
            tls_port: 'optional port to check cert for Domain Name (default: 443). Will not execute if proxy parameter is set.',
            results_file: 'optional - File to write results to (default: /tmp/parent_domain-timestamp-pwn_bruteforce_subdomains.txt)'
          )

          #{self}.authors
        "
      end
    end
  end
end
