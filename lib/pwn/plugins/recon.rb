# frozen_string_literal: true

require 'json'
require 'open3'
require 'net/http'
require 'uri'
require 'timeout'
require 'socket'
require 'openssl'
require 'digest'
require 'fileutils'
require 'securerandom'
require 'time'
require 'rexml/document'

module PWN
  module Plugins
    # subfinder/httpx/masscan wrappers + cert-transparency (crt.sh, certspotter).
    module Recon
      UA = 'pwn-recon/1.0'

      public_class_method def self.required_bins
        %w[subfinder httpx masscan amass]
      end

      # Persisted asset IDs are the join key for Context ingestion and Findings.
      public_class_method def self.run(opts = {})
        target = opts[:target].to_s
        raise ArgumentError, 'target must be a single hostname or IP' unless target.match?(/\A[a-zA-Z0-9][a-zA-Z0-9.:-]*\z/)

        engagement = opts.fetch(:engagement_id, 'default').to_s
        raise ArgumentError, 'engagement_id must be a simple identifier' unless engagement.match?(/\A[a-zA-Z0-9_-]+\z/)

        modules = opts.fetch(:modules, %w[nmap banner]).map(&:to_s)
        raise ArgumentError, 'modules must contain nmap, banner, tls, subfinder or nuclei' if modules.empty? || (modules - %w[nmap banner tls subfinder nuclei]).any?

        ports = Array(opts.fetch(:ports, [80, 443]))
        raise ArgumentError, 'ports must be integers in 1..65535' unless !ports.empty? && ports.all? { |port| port.is_a?(Integer) && port.between?(1, 65_535) }

        timeout = Float(opts.fetch(:timeout, 15))
        raise ArgumentError, 'timeout must be in 0..300 seconds' unless timeout.positive? && timeout <= 300

        dir = File.join(File.expand_path(opts[:root] || '~/.pwn/engagements'), engagement, 'recon')
        FileUtils.mkdir_p(dir)
        assets = []
        results = modules.uniq.map do |name|
          probe_errors = []
          evidence = File.join(dir, "#{SecureRandom.hex(8)}-#{name}.#{name == 'nmap' ? 'xml' : 'json'}")
          observations = if name == 'nmap'
                           xml = pipeline_command(argv: ['nmap', '-n', '-Pn', '-sT', '-p', ports.uniq.join(','), '-oX', '-', target], timeout: timeout)
                           File.write(evidence, xml)
                           doc = REXML::Document.new(xml)
                           REXML::XPath.match(doc, '//host').flat_map do |host|
                             address = host.elements['address']&.attributes&.[]('addr') || target
                             REXML::XPath.match(host, 'ports/port').filter_map do |port|
                               next unless port.elements['state']&.attributes&.[]('state') == 'open'

                               { address: address, port: port.attributes['portid'].to_i, protocol: port.attributes['protocol'],
                                 source: name, state: 'open', service: port.elements['service']&.attributes&.[]('name') }
                             end
                           end
                         elsif %w[subfinder nuclei].include?(name)
                           argv = name == 'subfinder' ? ['subfinder', '-silent', '-d', target] : ['nuclei', '-silent', '-jsonl', '-duc', '-u', target]
                           output = pipeline_command(argv: argv, timeout: timeout)
                           rows = output.lines.reject { |line| line.strip.empty? }.map do |line|
                             if name == 'subfinder'
                               { address: line.strip.downcase, protocol: 'host', port: nil, source: name }
                             else
                               row = JSON.parse(line)
                               host = URI(row['host'].to_s)
                               { address: host.host || target, protocol: 'tcp', port: host.port,
                                 source: name, template_id: row['template-id'], matched_at: row['matched-at'],
                                 scanner_severity: row.dig('info', 'severity'), classification: 'scanner_observation' }
                             end
                           end.uniq
                           File.write(evidence, JSON.pretty_generate(rows))
                           rows
                         else
                           rows = ports.filter_map do |port|
                             Socket.tcp(target, port, connect_timeout: timeout) do |socket|
                               data = if name == 'tls'
                                        context = OpenSSL::SSL::SSLContext.new
                                        context.verify_mode = OpenSSL::SSL::VERIFY_NONE
                                        ssl = OpenSSL::SSL::SSLSocket.new(socket, context)
                                        ssl.hostname = target
                                        begin
                                          Timeout.timeout(timeout) { ssl.connect }
                                          cert = ssl.peer_cert
                                          { subject: cert.subject.to_s, issuer: cert.issuer.to_s,
                                            not_before: cert.not_before.utc.iso8601, not_after: cert.not_after.utc.iso8601,
                                            certificate_sha256: Digest::SHA256.hexdigest(cert.to_der),
                                            san: cert.extensions.find { |ext| ext.oid == 'subjectAltName' }&.value,
                                            tls_version: ssl.ssl_version, trust_verified: false }
                                        ensure
                                          ssl.close
                                        end
                                      else
                                        banner = Timeout.timeout(timeout) { socket.readpartial(4096) }
                                        { banner: banner.encode('UTF-8', invalid: :replace, undef: :replace) }
                                      end
                               { address: socket.remote_address.ip_address, port: port, protocol: 'tcp', source: name }.merge(data)
                             end
                           rescue StandardError => e
                             probe_errors << { port: port, error: "#{e.class}: #{e.message}" }
                             nil
                           end
                           File.write(evidence, JSON.pretty_generate(rows))
                           rows
                         end
          observations.each do |row|
            id = "asset-#{Digest::SHA256.hexdigest([row[:address].downcase, row[:protocol], row[:port]].join('|'))[0, 24]}"
            assets << { id: id, address: row[:address], protocol: row[:protocol], port: row[:port],
                        observations: [row], evidence_paths: [evidence] }
          end
          status = if probe_errors.empty?
                     'ok'
                   else
                     (observations.empty? ? 'error' : 'partial')
                   end
          { name: name, status: status, evidence_path: evidence, errors: probe_errors }
        rescue Errno::ENOENT => e
          { name: name, status: 'unavailable', error: e.message }
        rescue StandardError => e
          { name: name, status: 'error', error: "#{e.class}: #{e.message}" }
        end
        path = File.join(dir, 'assets.json')
        File.open("#{path}.lock", 'a') do |lock|
          lock.flock(File::LOCK_EX)
          previous = File.file?(path) ? JSON.parse(File.read(path), symbolize_names: true).fetch(:assets) : []
          merged = (previous + assets).group_by { |row| row[:id] }.map do |_id, rows|
            rows.last.merge(observations: rows.flat_map { |row| row[:observations] }.uniq,
                            evidence_paths: rows.flat_map { |row| row[:evidence_paths] }.uniq)
          end
          merged.sort_by! { |row| row[:id] }
          payload = { schema_version: 1, engagement_id: engagement, assets: merged, modules: results }
          temp = "#{path}.#{SecureRandom.hex(8)}.tmp"
          File.write(temp, JSON.pretty_generate(payload))
          File.rename(temp, path)
        end
        result = JSON.parse(File.read(path), symbolize_names: true).merge(path: path)
        result[:loot] = harvest_loot(assets: result[:assets], engagement_id: engagement)
        if opts[:ingest]
          begin
            ingestor = opts[:ingestor] || PWN::AI::Context.method(:ingest)
            result[:ingestion] = ingestor.call(path, session_id: engagement, **opts[:ingest_options] || {})
          rescue StandardError => e
            result[:ingestion] = { status: 'error', error: "#{e.class}: #{e.message}" }
          end
        end
        result
      end

      private_class_method def self.pipeline_command(opts = {})
        Open3.popen3(*opts[:argv], pgroup: true) do |stdin, stdout, stderr, wait|
          stdin.close
          output = Thread.new { stdout.read }
          errors = Thread.new { stderr.read }
          begin
            Timeout.timeout(opts[:timeout]) do
              status = wait.value
              raise "command failed (#{status.exitstatus}): #{errors.value}" unless status.success?

              output.value
            end
          rescue Timeout::Error
            begin
              Process.kill('KILL', -wait.pid)
            rescue StandardError
              nil
            end
            wait.value
            raise
          ensure
            output.join
            errors.join
          end
        end
      end

      public_class_method def self.subdomains(opts = {})
        domain = opts[:domain].to_s.downcase.strip
        raise 'ERROR: domain is required' if domain.empty?

        names = []
        if PWN::Plugins::PreflightChecker.bin?(name: 'subfinder')
          stdout, = Open3.capture3('subfinder', '-silent', '-d', domain)
          names.concat(stdout.lines.map(&:strip).reject(&:empty?))
        end
        if PWN::Plugins::PreflightChecker.bin?(name: 'amass')
          stdout, = Open3.capture3('amass', 'enum', '-passive', '-d', domain, '-nocolor')
          names.concat(stdout.lines.map(&:strip).reject(&:empty?))
        end
        names.concat(Array(crt_sh(domain: domain)))
        normalize_names(names: names, domain: domain)
      end

      public_class_method def self.httpx(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'httpx')
        hosts = Array(opts[:hosts] || opts[:urls])
        stdout, = Open3.capture3('httpx', '-silent', '-json', stdin_data: "#{hosts.join("\n")}\n")
        stdout.each_line.filter_map do |ln|
          JSON.parse(ln)
        rescue JSON::ParserError
          nil
        end
      end

      public_class_method def self.masscan(opts = {})
        bin = %w[masscan naabu].find { |b| PWN::Plugins::PreflightChecker.bin?(name: b) }
        raise PWN::Plugins::PreflightChecker::MissingBinary, 'ERROR: masscan/naabu missing' unless bin

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

      public_class_method def self.amass(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'amass')
        domain = opts[:domain].to_s
        raise 'ERROR: domain is required' if domain.empty?

        stdout, = Open3.capture3('amass', 'enum', '-passive', '-d', domain, '-nocolor')
        stdout.lines.map(&:strip).reject(&:empty?)
      end

      public_class_method def self.passive_dns(opts = {})
        domain = opts[:domain].to_s.downcase.strip
        raise 'ERROR: domain is required' if domain.empty?

        uri = URI("https://api.hackertarget.com/hostsearch/?q=#{URI.encode_www_form_component(domain)}")
        rows = http_json(url: uri.to_s, timeout: opts[:timeout] || 8)
        Array(rows)
      rescue StandardError => e
        { error: "#{e.class}: #{e.message}", domain: domain }
      end

      # Harvest credential strings from recon assets into the encrypted loot store.
      public_class_method def self.harvest_loot(opts = {})
        eng = opts[:engagement_id] || opts[:engagement]
        Array(opts[:assets]).flat_map do |asset|
          asset = asset.transform_keys(&:to_sym) if asset.is_a?(Hash)
          host = (asset[:address] || asset[:host]).to_s
          Array(asset[:observations]).flat_map do |obs|
            obs = obs.transform_keys(&:to_sym) if obs.is_a?(Hash)
            blob = [obs[:banner], obs[:body], obs[:text], obs[:matched_at]].compact.join("\n")
            next [] if blob.empty?

            PWN::Plugins::Vault.ingest(
              text: blob,
              host: host,
              source: 'recon',
              where: opts[:where] || "banner:#{obs[:port] || asset[:port]}",
              engagement: eng,
              finding_id: opts[:finding_id]
            )
          end
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Normalize explicit scan modules and persist stable evidence-backed asset IDs.
          #{self}.run(
            target: 'required - single hostname or IP',
            modules: 'optional - Array nmap/banner/tls/subfinder/nuclei; defaults nmap/banner',
            ports: 'optional - Array of integer ports; defaults 80 and 443',
            engagement_id: 'optional - simple identifier; defaults default',
            root: 'optional - engagements directory; defaults ~/.pwn/engagements',
            timeout: 'optional - per-operation timeout seconds; defaults 15, maximum 300',
            ingest: 'optional - invoke Context.ingest after persistence; defaults false',
            ingestor: 'optional - callable(path, **options) replacing Context.ingest',
            ingest_options: 'optional - Hash passed to the ingestor'
          )

          # Harvest credential strings from recon assets into the encrypted loot store.
          #{self}.harvest_loot(
            assets: 'required - Array of recon asset hashes with address and observations',
            engagement_id: 'optional - engagement id scoping the loot file (defaults to default)',
            engagement: 'optional - alias for engagement_id',
            where: 'optional - provenance path overlay when observation port is missing',
            finding_id: 'optional - finding id linked onto harvested secrets'
          )

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

          # Passive amass enum (requires amass).
          #{self}.amass(
            domain: 'required - FQDN to query (e.g. example.com)'
          )

          # Passive DNS hostsearch for a domain (hackertarget).
          #{self}.passive_dns(
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
