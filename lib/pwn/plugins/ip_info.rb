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
      # PWN::Plugins::IPInfo.get(
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
      #   ip_or_host: 'required - IP or Host to lookup',
      #   proxy: 'optional - use a proxy',
      #   tls_port: 'optional port to check cert for Domain Name (default: 443). Will not execute if proxy parameter is set.'
      # )

      public_class_method def self.get(opts = {})
        ip_or_host = opts[:ip_or_host].to_s.scrub.strip.chomp
        proxy = opts[:proxy]
        tls_port = opts[:tls_port]
        tls_port ||= 443

        ip_info_resp = []
        if IPAddress.valid?(ip_or_host)
          if proxy
            ip_resp_json = ip_info_rest_call(ip: ip_or_host, proxy: proxy)
          else
            ip_resp_json = ip_info_rest_call(ip: ip_or_host)
          end

          ip_info_resp.push(ip_resp_json)
        else
          Resolv::DNS.new.each_address(ip_or_host) do |ip|
            ip_info_resp.push(ip_info_rest_call(ip: ip))
          end
        end

        if proxy.nil?
          ip_info_resp.each do |ip_resp|
            # TODO: add this block as a method in PWN::Plugins::Sock
            tls_port_avail = PWN::Plugins::Sock.check_port_in_use(
              server_ip: ip_or_host,
              server_port: tls_port
            )

            ip_resp[:tls_avail] = tls_port_avail
            next unless tls_port_avail

            tls_sock_obj = PWN::Plugins::Sock.connect(
              target: ip_or_host,
              port: tls_port,
              protocol: :tcp,
              tls: true
            )
            tls_sock_obj.sync_close = true
            cert = tls_sock.peer_cert
            ip_resp[:cert_txt] = cert.to_text
            ip_resp[:cert_obj] = cert
            PWN::Plugins::Sock.disconnect(sock_obj: tls_sock_obj)
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
            ip_or_host: 'required - IP or Host to lookup',
            proxy: 'optional - use a proxy',
            tls_port: 'optional port to check cert for Domain Name (default: 443). Will not execute if proxy parameter is set.'
          )

          #{self}.authors
        "
      end
    end
  end
end
