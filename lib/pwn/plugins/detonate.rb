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

        {
          error: 'sample execution backend is not implemented; refusing synthetic detonation',
          path: path,
          network: net,
          timeout: timeout,
          isolated: false,
          executed: false
        }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Validate the sample and report unavailable execution honestly; never run it on the host.
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
