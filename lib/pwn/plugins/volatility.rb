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
        bin = %w[vol volatility3 vol3].find { |b| PWN::Plugins::Doctor.bin?(name: b) }
        raise PWN::Plugins::Doctor::MissingBinary, 'ERROR: volatility3 (vol) missing' unless bin

        memory = opts[:memory] || opts[:file]
        plugin = opts[:plugin] || 'windows.pslist'
        raise 'ERROR: memory is required' if memory.to_s.empty?

        stdout, stderr, status = Open3.capture3(bin, '-f', memory.to_s, plugin.to_s)
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

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
