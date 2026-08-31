# frozen_string_literal: true

require 'json'
require 'open3'

module PWN
  module Plugins
    # semgrep wrapper feeding SAST-shaped findings.
    module Semgrep
      public_class_method def self.required_bins
        %w[semgrep]
      end

      public_class_method def self.scan(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'semgrep')
        target = opts[:path] || opts[:target] || '.'
        cmd = ['semgrep', '--json', '--quiet']
        cmd += ['--config', opts[:config].to_s] if opts[:config]
        cmd << target.to_s
        stdout, stderr, status = Open3.capture3(*cmd)
        parsed = begin
          JSON.parse(stdout)
        rescue JSON::ParserError
          {}
        end
        findings = Array(parsed['results']).map do |r|
          {
            title: r['check_id'],
            severity: r.dig('extra', 'severity'),
            path: r['path'],
            line: r.dig('start', 'line'),
            message: r.dig('extra', 'message')
          }
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

          # Run semgrep --json and map results into finding hashes.
          #{self}.scan(
            path: 'optional - directory or file to scan (defaults to .)',
            target: 'optional - alias for path',
            config: 'optional - semgrep --config value (e.g. auto or p/owasp-top-ten)'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
