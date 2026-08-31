# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # sqlmap wrapper to pair with SAST SQL detection.
    module Sqlmap
      public_class_method def self.required_bins
        %w[sqlmap]
      end

      public_class_method def self.run(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'sqlmap')
        url = opts[:url].to_s
        raise 'ERROR: url is required' if url.empty?

        cmd = ['sqlmap', '-u', url, '--batch', '--level', (opts[:level] || 1).to_s]
        cmd += ['--data', opts[:data].to_s] if opts[:data]
        cmd << '--dbs' if opts[:dbs]
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run run and return its result
          #{self}.run(
            url: 'required - HTTP(S) URL',
            level: 'optional - level value consumed by #run',
            data: 'optional - data value consumed by #run',
            dbs: 'optional - dbs value consumed by #run'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
