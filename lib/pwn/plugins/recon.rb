# frozen_string_literal: true

require 'json'
require 'open3'
require 'net/http'
require 'uri'
require 'timeout'

module PWN
  module Plugins
    # subfinder/httpx/masscan wrappers + cert-transparency (crt.sh, certspotter).
    module Recon
      UA = 'pwn-recon/1.0'

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.subdomains(opts = {})
        domain = opts[:domain].to_s.downcase.strip
        raise 'ERROR: domain is required' if domain.empty?

        names = []
        if PWN::Plugins::Doctor.bin?(name: 'subfinder')
          stdout, = Open3.capture3('subfinder', '-silent', '-d', domain)
          names.concat(stdout.lines.map(&:strip).reject(&:empty?))
        end
        names.concat(Array(crt_sh(domain: domain)))
        normalize_names(names: names, domain: domain)
      end

      public_class_method def self.httpx(opts = {})
        PWN::Plugins::Doctor.require_bin!(name: 'httpx')
        hosts = Array(opts[:hosts] || opts[:urls])
        stdout, = Open3.capture3('httpx', '-silent', '-json', stdin_data: "#{hosts.join("\n")}\n")
        stdout.each_line.filter_map do |ln|
          JSON.parse(ln)
        rescue JSON::ParserError
          nil
        end
      end

      public_class_method def self.masscan(opts = {})
        bin = %w[masscan naabu].find { |b| PWN::Plugins::Doctor.bin?(name: b) }
        raise PWN::Plugins::Doctor::MissingBinary, 'ERROR: masscan/naabu missing' unless bin

        target = opts[:target].to_s
        ports = (opts[:ports] || '1-1024').to_s
        stdout, = Open3.capture3(bin, '-p', ports, target)
        stdout
      end

      public_class_method def self.crt_sh(opts = {})
        domain = opts[:domain].to_s.downcase.strip
        raise 'ERROR: domain is required' if domain.empty?

        errors = []
        names = []
        sources = [
          "https://api.certspotter.com/v1/issuances?domain=#{URI.encode_www_form_component(domain)}&include_subdomains=true&expand=dns_names",
          "https://crt.sh/?q=#{URI.encode_www_form_component(domain)}&output=json",
          "https://crt.sh/?q=#{URI.encode_www_form_component("%.#{domain}")}&output=json"
        ]
        sources.each do |url|
          next if !names.empty? && url.include?('crt.sh')

          rows = http_json(url: url, timeout: url.include?('crt.sh') ? 8 : (opts[:timeout] || 15))
          names.concat(extract_dns_names(rows: rows))
        rescue StandardError => e
          errors << "#{URI(url).host}: #{e.class}: #{e.message}"
        end
        out = normalize_names(names: names, domain: domain)
        return out unless out.empty?

        raise "ERROR: cert-transparency lookup failed for #{domain} (#{errors.join('; ')})"
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run subdomains and return its result
          #{self}.subdomains(
            domain: 'required - FQDN to query (e.g. example.com)'
          )

          # Run httpx and return its result
          #{self}.httpx(
            hosts: 'optional - Array of hostnames or URLs to probe',
            urls: 'optional - Array of HTTP(S) URLs'
          )

          # Run masscan and return its result
          #{self}.masscan(
            target: 'optional - hostname, IP, or CIDR to scan',
            ports: 'optional - port, list, or range (e.g. 22,80,443 or 1-1024)'
          )

          # Run crt sh and return its result
          #{self}.crt_sh(
            domain: 'required - FQDN to query (e.g. example.com)',
            timeout: 'optional - seconds to wait before giving up'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.http_json(opts = {})
        uri = URI(opts[:url].to_s)
        timeout = (opts[:timeout] || 15).to_i
        req = Net::HTTP::Get.new(uri)
        req['User-Agent'] = UA
        req['Accept'] = 'application/json'
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == 'https')
        http.open_timeout = [timeout, 8].min
        http.read_timeout = timeout
        http.max_retries = 0
        res = Timeout.timeout(timeout + 2) { http.request(req) }
        raise "HTTP #{res.code}" unless res.is_a?(Net::HTTPSuccess)

        body = res.body.to_s
        raise JSON::ParserError, body[0, 120] unless body.lstrip.start_with?('[', '{')

        JSON.parse(body)
      end

      private_class_method def self.extract_dns_names(opts = {})
        rows = opts[:rows]
        return [] if rows.nil?

        Array(rows).flat_map do |row|
          next [] unless row.is_a?(Hash)

          vals = []
          vals.concat(Array(row['dns_names'] || row[:dns_names]))
          vals.concat(row['name_value'].to_s.split(/[\s,]+/))
          vals.concat(row['common_name'].to_s.split(/[\s,]+/))
          vals
        end
      end

      private_class_method def self.normalize_names(opts = {})
        domain = opts[:domain].to_s.downcase
        Array(opts[:names]).map { |n| n.to_s.strip.downcase.delete_prefix('*.') }
                           .reject(&:empty?)
                           .select { |n| n == domain || n.end_with?(".#{domain}") }
                           .uniq
                           .sort
      end
    end
  end
end
