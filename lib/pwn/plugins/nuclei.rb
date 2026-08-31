# frozen_string_literal: true

require 'json'
require 'open3'

module PWN
  module Plugins
    # nuclei wrapper: template/severity, JSONL findings.
    module Nuclei
      public_class_method def self.required_bins
        %w[nuclei]
      end

      public_class_method def self.scan(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'nuclei')
        target = opts[:target] || opts[:url]
        raise 'ERROR: target is required' if target.to_s.empty?

        cmd = ['nuclei', '-u', target.to_s, '-jsonl', '-silent']
        cmd += ['-severity', opts[:severity].to_s] if opts[:severity]
        cmd += ['-t', opts[:templates].to_s] if opts[:templates]
        cmd += ['-rate-limit', opts[:rate_limit].to_s] if opts[:rate_limit]
        stdout, stderr, status = Open3.capture3(*cmd)
        findings = stdout.each_line.filter_map do |ln|
          JSON.parse(ln)
        rescue JSON::ParserError
          nil
        end
        { findings: to_findings(rows: findings), raw: findings, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.to_findings(opts = {})
        Array(opts[:rows] || opts[:findings]).map do |r|
          r = r.transform_keys(&:to_s) if r.is_a?(Hash)
          info = r['info'] || {}
          info = info.transform_keys(&:to_s) if info.is_a?(Hash)
          {
            title: info['name'] || r['template-id'] || 'nuclei finding',
            severity: (info['severity'] || 'info').to_s,
            url: r['matched-at'] || r['host'],
            template: r['template-id'],
            description: info['description']
          }
        end
      end

      public_class_method def self.to_defectdojo(opts = {})
        to_findings(opts).map do |f|
          { title: f[:title], severity: f[:severity], description: "#{f[:url]} #{f[:template]}".strip }
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run scan and return its result
          #{self}.scan(
            target: 'required - hostname, IP, or CIDR to scan (defaults to opts[:url])',
            url: 'optional - HTTP(S) URL',
            severity: 'optional - severity value consumed by #scan',
            templates: 'optional - templates value consumed by #scan',
            rate_limit: 'optional - requests per second passed to nuclei -rate-limit'
          )

          # Map nuclei JSONL rows into report-shaped finding hashes.
          #{self}.to_findings(
            rows: 'optional - Array of parsed nuclei JSONL objects',
            findings: 'optional - alias for rows'
          )

          # Shape findings for a DefectDojo import payload.
          #{self}.to_defectdojo(
            rows: 'optional - Array of parsed nuclei JSONL objects',
            findings: 'optional - alias for rows'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
