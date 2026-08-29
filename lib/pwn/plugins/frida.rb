# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # Frida attach/spawn + script injection.
    module Frida
      public_class_method def self.required_bins
        %w[frida]
      end

      public_class_method def self.ps(opts = {})
        PWN::Plugins::Doctor.require_bin!(name: 'frida')
        stdout, stderr, status = Open3.capture3('frida-ps', *Array(opts[:extra]))
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.attach(opts = {})
        PWN::Plugins::Doctor.require_bin!(name: 'frida')
        target = opts[:target] || opts[:name]
        script = opts[:script].to_s
        raise 'ERROR: target is required' if target.to_s.empty?

        cmd = ['frida', '-n', target.to_s]
        cmd += ['-l', opts[:script_path].to_s] if opts[:script_path]
        cmd += ['-e', script] unless script.empty?
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

          # Run ps and return its result
          #{self}.ps(
            extra: 'optional - Array extra value consumed by #ps'
          )

          # Run attach and return its result
          #{self}.attach(
            target: 'required - hostname, IP, or CIDR to scan (defaults to opts[:name])',
            name: 'optional - binary or identifier name',
            script: 'required - script value consumed by #attach',
            script_path: 'optional - script path value consumed by #attach'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
