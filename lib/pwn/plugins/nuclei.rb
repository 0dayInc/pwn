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
        PWN::Plugins::Doctor.require_bin!(name: 'nuclei')
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
        { findings: findings, stderr: stderr, exit: status.exitstatus }
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
            rate_limit: 'optional - rate limit value consumed by #scan'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
