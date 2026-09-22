# frozen_string_literal: true

require 'open3'
require 'json'

module PWN
  module Plugins
    # Generic lockfile/image CVE scan with engine selection.
    module SBOM
      public_class_method def self.required_bins
        []
      end

      public_class_method def self.scan(opts = {})
        target = (opts[:path_or_image] || opts[:path] || opts[:image]).to_s
        raise ArgumentError, 'path_or_image is required' if target.empty?

        engine = (opts[:engine] || select_engine(target: target)).to_s
        rows = case engine
               when 'grype' then parse_grype(target: target)
               when 'trivy' then parse_trivy(target: target)
               when 'osv-scanner' then parse_osv(target: target)
               when 'syft+grype', 'syft'
                 inv = parse_syft(target: target)
                 if PWN::Plugins::PreflightChecker.bin?(name: 'grype')
                   parse_grype(target: target)
                 else
                   inv
                 end
               else
                 raise IOError, 'no SBOM engine installed (syft, grype, trivy, or osv-scanner)'
               end
        observations = []
        if defined?(PWN::Plugins::Recon) && opts[:record] == true
          rows.each do |row|
            next if row[:cve].to_s.empty?

            observations << PWN::Plugins::Recon.observe(
              host: target,
              product: row[:package].to_s,
              version: row[:version].to_s,
              evidence_path: target,
              source: 'sbom',
              lead: "#{row[:package]} #{row[:cve]}",
              engagement_id: opts[:engagement_id]
            )
          end
        end
        { engine: engine, target: target, vulns: rows, observations: observations }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Scan a lockfile or image with the first available engine.
          #{self}.scan(
            path_or_image: 'required - lockfile, directory, or image reference',
            path: 'optional - alias for path_or_image',
            image: 'optional - alias for path_or_image',
            engine: 'optional - syft, grype, trivy, or osv-scanner',
            record: 'optional - true stores each CVE as a recon observation, not a finding',
            engagement_id: 'optional - engagement identifier for the observation'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.select_engine(opts = {})
        _target = opts[:target]
        %w[grype trivy osv-scanner syft].find { |bin| PWN::Plugins::PreflightChecker.bin?(name: bin) }
      end

      private_class_method def self.run!(opts = {})
        argv = opts[:argv]
        if Open3.respond_to?(:capture3)
          out, err, st = Open3.capture3(*argv)
          raise IOError, "#{argv.first} failed: #{err}" unless st.success? || opts[:allow_nonzero] == true

        else
          out, = Open3.capture2(*argv)
        end
        out
      rescue Errno::ENOENT
        out, = Open3.capture2(*opts[:argv])
        out
      end

      private_class_method def self.parse_grype(opts = {})
        out = run!(argv: ['grype', '-o', 'json', opts[:target]], allow_nonzero: true)
        json = JSON.parse(out)
        Array(json['matches']).map do |row|
          art = row['artifact'] || {}
          vuln = row['vulnerability'] || {}
          normalize(package: art['name'], version: art['version'], cve: vuln['id'], severity: vuln['severity'], fix: vuln.dig('fix', 'versions'))
        end
      end

      private_class_method def self.parse_trivy(opts = {})
        target = opts[:target].to_s
        sub = File.file?(target) && target.match?(/\.(tar|tar\.gz|tgz|tar\.zst)\z/i) ? 'image' : 'fs'
        sub = 'image' if target.include?(':') && !File.exist?(target)
        out = run!(argv: ['trivy', sub, '--format', 'json', target], allow_nonzero: true)
        json = JSON.parse(out)
        Array(json['Results']).flat_map do |res|
          Array(res['Vulnerabilities']).map do |vuln|
            normalize(package: vuln['PkgName'], version: vuln['InstalledVersion'], cve: vuln['VulnerabilityID'], severity: vuln['Severity'], fix: vuln['FixedVersion'])
          end
        end
      end

      private_class_method def self.parse_osv(opts = {})
        target = opts[:target].to_s
        argv = ['osv-scanner', '--json']
        argv.concat(File.file?(target) ? [target] : ['-r', target])
        out = run!(argv: argv, allow_nonzero: true)
        json = JSON.parse(out)
        Array(json['results']).flat_map do |res|
          Array(res['packages']).flat_map do |pkg|
            Array(pkg['vulnerabilities']).map do |vuln|
              normalize(package: pkg.dig('package', 'name'), version: pkg.dig('package', 'version'), cve: vuln['id'], severity: 'unknown', fix: nil)
            end
          end
        end
      end

      private_class_method def self.parse_syft(opts = {})
        out = run!(argv: ['syft', '-o', 'json', opts[:target]])
        json = JSON.parse(out)
        Array(json['artifacts']).map do |art|
          normalize(package: art['name'], version: art['version'], cve: nil, severity: 'info', fix: nil)
        end
      end

      private_class_method def self.normalize(opts = {})
        {
          package: opts[:package].to_s,
          version: opts[:version].to_s,
          cve: opts[:cve].to_s,
          severity: opts[:severity].to_s.downcase,
          fix_version: Array(opts[:fix]).first.to_s
        }
      end
    end
  end
end
