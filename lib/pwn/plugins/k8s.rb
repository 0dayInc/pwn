# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # trivy / kube-hunter wrappers plus docker-socket preflight.
    module K8s
      public_class_method def self.required_bins
        %w[trivy]
      end

      public_class_method def self.trivy(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'trivy')
        target = opts[:target] || opts[:image] || opts[:path]
        raise 'ERROR: target is required' if target.to_s.empty?

        mode = (opts[:mode] || :image).to_s
        cmd = ['trivy', mode, '--format', 'json', target.to_s]
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.kube_hunter(opts = {})
        return { error: 'kube-hunter missing', hint: 'pip install kube-hunter' } unless PWN::Plugins::PreflightChecker.bin?(name: 'kube-hunter')

        cmd = ['kube-hunter']
        cmd += ['--remote', opts[:remote].to_s] if opts[:remote]
        cmd << '--report' << 'json'
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.docker_socket?(opts = {})
        path = (opts[:path] || '/var/run/docker.sock').to_s
        PWN::Plugins::PreflightChecker.service?(name: 'docker', path: path)
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Scan a container image or filesystem with trivy.
          #{self}.trivy(
            target: 'required - image name or path',
            image: 'optional - alias for target',
            path: 'optional - alias for target',
            mode: 'optional - trivy subcommand (defaults to image)'
          )

          # Run kube-hunter (remote cluster optional).
          #{self}.kube_hunter(
            remote: 'optional - API server host for --remote'
          )

          # True when the docker unix socket is present.
          #{self}.docker_socket?(
            path: 'optional - socket path (defaults to /var/run/docker.sock)'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
