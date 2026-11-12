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
               when 'trivy' then parse_trivy(target: target, image: opts[:image] && !opts[:path_or_image] && !opts[:path])
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
        return engine_failure(engine: engine, target: target, exit: rows[:exit]) if rows.is_a?(Hash) && rows[:ok] == false

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
        out, st = Open3.capture2(*argv)
        exit_code = st.success? ? 0 : st.exitstatus
        accepted = st.success? || Array(opts[:accepted_exits]).include?(exit_code)
        { output: accepted ? out : '', exit: exit_code, ok: accepted }
      end

      private_class_method def self.engine_failure(opts = {})
        { engine: opts[:engine].to_s, target: opts[:target].to_s, vulns: [], observations: [], ok: false, success: false, status: 'failed', error: "#{opts[:engine]} failed", exit: opts[:exit] }
      end

      private_class_method def self.parse_grype(opts = {})
        ran = run!(argv: ['grype', '-o', 'json', opts[:target]])
        return ran unless ran[:ok]
        return engine_failure(engine: 'grype', target: opts[:target], exit: ran[:exit]) if ran[:output].to_s.strip.empty?

        json = parse_engine_json(text: ran[:output])
        matches = json['matches'] || json[:matches] if json.is_a?(Hash)
        return engine_failure(engine: 'grype', target: opts[:target], exit: ran[:exit]) unless matches.is_a?(Array)

        matches.map do |row|
          art = row['artifact'] || row[:artifact] || {}
          vuln = row['vulnerability'] || row[:vulnerability] || {}
          normalize(package: art['name'] || art[:name], version: art['version'] || art[:version], cve: vuln['id'] || vuln[:id], severity: vuln['severity'] || vuln[:severity], fix: vuln.dig('fix', 'versions') || vuln.dig(:fix, :versions))
        end
      end

      private_class_method def self.parse_trivy(opts = {})
        target = opts[:target].to_s
        sub = File.file?(target) && target.match?(/\.(tar|tar\.gz|tgz|tar\.zst)\z/i) ? 'image' : 'fs'
        sub = 'image' if opts[:image] || (target.include?(':') && !File.exist?(target))
        ran = run!(argv: ['trivy', sub, '--format', 'json', target])
        return engine_failure(engine: 'trivy', target: target, exit: ran[:exit]) unless ran[:ok]

        json = parse_engine_json(text: ran[:output])
        results = json['Results'] || json[:Results] if json.is_a?(Hash)
        return engine_failure(engine: 'trivy', target: target, exit: ran[:exit]) unless results.is_a?(Array)

        results.flat_map do |res|
          Array(res['Vulnerabilities'] || res[:Vulnerabilities]).map do |vuln|
            normalize(package: vuln['PkgName'] || vuln[:PkgName], version: vuln['InstalledVersion'] || vuln[:InstalledVersion], cve: vuln['VulnerabilityID'] || vuln[:VulnerabilityID], severity: vuln['Severity'] || vuln[:Severity], fix: vuln['FixedVersion'] || vuln[:FixedVersion])
          end
        end
      end

      private_class_method def self.parse_osv(opts = {})
        target = opts[:target].to_s
        argv = ['osv-scanner', '--json']
        argv.concat(File.file?(target) ? [target] : ['-r', target])
        ran = run!(argv: argv, accepted_exits: [1])
        return engine_failure(engine: 'osv-scanner', target: target, exit: ran[:exit]) unless ran[:ok]

        json = parse_engine_json(text: ran[:output])
        results = json['results'] || json[:results] if json.is_a?(Hash)
        return engine_failure(engine: 'osv-scanner', target: target, exit: ran[:exit]) unless results.is_a?(Array)

        results.flat_map do |res|
          Array(res['packages'] || res[:packages]).flat_map do |pkg|
            package = pkg['package'] || pkg[:package] || {}
            Array(pkg['vulnerabilities'] || pkg[:vulnerabilities]).map do |vuln|
              normalize(package: package['name'] || package[:name], version: package['version'] || package[:version], cve: vuln['id'] || vuln[:id], severity: 'unknown', fix: nil)
            end
          end
        end
      end

      private_class_method def self.parse_syft(opts = {})
        ran = run!(argv: ['syft', '-o', 'json', opts[:target]])
        return engine_failure(engine: 'syft', target: opts[:target], exit: ran[:exit]) unless ran[:ok]

        json = parse_engine_json(text: ran[:output])
        artifacts = json['artifacts'] || json[:artifacts] if json.is_a?(Hash)
        return engine_failure(engine: 'syft', target: opts[:target], exit: ran[:exit]) unless artifacts.is_a?(Array)

        artifacts.map do |art|
          normalize(package: art['name'] || art[:name], version: art['version'] || art[:version], cve: nil, severity: 'info', fix: nil)
        end
      end

      private_class_method def self.parse_engine_json(opts = {})
        JSON.parse(opts[:text].to_s)
      rescue JSON::ParserError
        nil
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
