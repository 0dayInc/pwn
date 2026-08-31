# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # volatility3 wrapper.
    module Volatility
      public_class_method def self.required_bins
        %w[vol]
      end

      public_class_method def self.run(opts = {})
        bin = %w[vol volatility3 vol3].find { |b| PWN::Plugins::PreflightChecker.bin?(name: b) }
        raise PWN::Plugins::PreflightChecker::MissingBinary, 'ERROR: volatility3 (vol) missing' unless bin

        memory = opts[:memory] || opts[:file]
        plugin = opts[:plugin] || 'windows.pslist'
        raise 'ERROR: memory is required' if memory.to_s.empty?

        stdout, stderr, status = Open3.capture3(bin, '-f', memory.to_s, plugin.to_s)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.yara(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'yara')
        rules = opts[:rules] || opts[:rule]
        target = opts[:memory] || opts[:file] || opts[:path]
        raise 'ERROR: rules and memory/file are required' if rules.to_s.empty? || target.to_s.empty?

        stdout, stderr, status = Open3.capture3('yara', rules.to_s, target.to_s)
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
            memory: 'required - memory value consumed by #run (defaults to opts[:file])',
            file: 'optional - filesystem path',
            plugin: 'required - plugin value consumed by #run (defaults to windows.pslist)'
          )

          # Scan a memory image with a yara rules file.
          #{self}.yara(
            rules: 'required - path to a .yar rules file',
            rule: 'optional - alias for rules',
            memory: 'required - memory image path',
            file: 'optional - alias for memory',
            path: 'optional - alias for memory'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
