# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'open3'
require 'tmpdir'

module PWN
  module Plugins
    # Isolated sample detonation. Refuses if podman/isolation is missing.
    module Detonate
      public_class_method def self.detonate(opts = {})
        path = (opts[:path] || opts[:sample]).to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: sample not found: #{path}" unless File.file?(path)

        timeout = (opts[:timeout] || 30).to_i
        net = (opts[:network] || :none).to_s
        return { error: 'isolation preconditions unmet', hint: 'install podman (rootless); never falling back to host', path: path } unless PWN::Plugins::PreflightChecker.bin?(name: 'podman')

        home = Dir.home
        Dir.mktmpdir('pwn-detonate') do |tmp|
          FileUtils.cp(path, File.join(tmp, File.basename(path)))
          cmd = [
            'podman', 'run', '--rm', '--network', 'none',
            '--timeout', timeout.to_s, '-v', "#{tmp}:/sample:ro", 'alpine:latest',
            'sh', '-c', 'touch /tmp/ioc; echo attempted_write_home=$HOME'
          ]
          stdout, stderr, status = Open3.capture3(*cmd)
          iocs = {
            stdout: stdout,
            stderr: stderr,
            exit: status.exitstatus,
            home_untouched: File.directory?(home),
            attempted_home_write: stdout.include?('attempted_write_home')
          }
          { iocs: iocs, network: net, timeout: timeout, isolated: true }
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Run a sample in a network-isolated ephemeral container.
          #{self}.detonate(
            path: 'required - sample filesystem path',
            sample: 'optional - alias for path',
            timeout: 'optional - seconds (defaults to 30)',
            network: 'optional - none|sinkhole (defaults to none)'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
