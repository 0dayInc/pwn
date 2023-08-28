# frozen_string_literal: true

require 'ipaddress'
require 'openssl'
require 'resolv'

module PWN
  module Plugins
    # This plugin leverages ip-api.com's REST API to discover information about IP addresses
    # 1,000 daily requests are allowed for free
    module IPInfo
      # Supported Method Parameters::
      # ip_resp_json = ip_info_rest_call(
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
          ip_resp_json = JSON.parse(
            ip_resp_str,
            symbolize_names: true
          )

          # Ensure the max number of IPs we can query / min = 120 to avoid being banned
          # Per http://ip-api.com/docs/api:json:
          # "Our system will automatically ban any IP address doing over 150 requests per minute"
          # To unban a banned IP, visit http://ip-api.com/docs/unban
          sleep 0.5

          ip_resp_json
        end
      rescue StandardError => e
        raise e
      end

      # Supported Method Parameters::
      # ip_info_struc = PWN::Plugins::IPInfo.get(
      #   target: 'required - IP or Host to lookup',
      #   proxy: 'optional - use a proxy',
      #   tls_port: 'optional port to check cert for Domain Name (default: 443). Will not execute if proxy parameter is set.'
      # )

      public_class_method def self.get(opts = {})
        target = opts[:target].to_s.scrub.strip.chomp
        proxy = opts[:proxy]
        tls_port = opts[:tls_port]
        tls_port ||= 443

        ip_info_resp = []
        if IPAddress.valid?(target)
          if proxy
            ip_resp_json = ip_info_rest_call(ip: target, proxy: proxy)
          else
            ip_resp_json = ip_info_rest_call(ip: target)
          end

          ip_info_resp.push(ip_resp_json)
        else
          Resolv::DNS.new.each_address(target) do |ip|
            ip_info_resp.push(ip_info_rest_call(ip: ip))
          end
        end

        if proxy.nil?
          ip_info_resp.each do |ip_resp|
            tls_port_avail = PWN::Plugins::Sock.check_port_in_use(
              server_ip: target,
              port: tls_port
            )

            ip_resp[:tls_avail] = tls_port_avail
            ip_resp[:cert_subject] = false
            ip_resp[:cert_issuer] = false
            ip_resp[:cert_serial] = false
            ip_resp[:not_before] = false
            ip_resp[:not_after] = false
            next unless tls_port_avail

            cert_obj = PWN::Plugins::Sock.get_tls_cert(
              target: target,
              port: tls_port
            )

            next unless cert_obj.is_a?(OpenSSL::X509::Certificate)

            ip_resp[:cert_subject] = cert_obj.subject.to_s
            ip_resp[:cert_issuer] = cert_obj.issuer.to_s
            ip_resp[:cert_serial] = cert_obj.serial.to_s
            ip_resp[:not_before] = cert_obj.not_before.to_s
            ip_resp[:not_after] = cert_obj.not_after.to_s
          end
        end

        ip_info_resp
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
          ip_info_struc = #{self}.get(
            target: 'required - IP or Host to lookup',
            proxy: 'optional - use a proxy',
            tls_port: 'optional port to check cert for Domain Name (default: 443). Will not execute if proxy parameter is set.'
          )

          #{self}.authors
        "
      end
    end
  end
end
