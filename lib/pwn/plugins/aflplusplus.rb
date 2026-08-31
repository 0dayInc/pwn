# frozen_string_literal: true

require 'open3'
require 'digest'

module PWN
  module Plugins
    # AFL++ campaign wrapper.
    module AFLplusplus
      public_class_method def self.required_bins
        %w[afl-fuzz]
      end

      public_class_method def self.fuzz(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'afl-fuzz')
        in_dir = opts[:in_dir] || opts[:corpus]
        out_dir = opts[:out_dir] || opts[:output]
        target = opts[:target]
        raise 'ERROR: in_dir, out_dir, and target are required' if in_dir.to_s.empty? || out_dir.to_s.empty? || target.to_s.empty?

        cmd = ['afl-fuzz', '-i', in_dir.to_s, '-o', out_dir.to_s, '--', target.to_s]
        cmd.concat(Array(opts[:args]))
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.crash_triage(opts = {})
        out_dir = (opts[:out_dir] || opts[:output]).to_s
        raise 'ERROR: out_dir is required' if out_dir.empty?

        crashes = Dir[File.join(out_dir, '**/crashes/id:*')]
        hashes = crashes.map { |p| [p, Digest::SHA256.file(p).hexdigest] }
        {
          crashes: crashes,
          unique: hashes.map(&:last).uniq,
          asan: crashes.any? { |p| File.binread(p).include?('AddressSanitizer') }
        }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run fuzz and return its result
          #{self}.fuzz(
            in_dir: 'required - in dir value consumed by #fuzz (defaults to opts[:corpus])',
            corpus: 'optional - corpus value consumed by #fuzz',
            out_dir: 'required - out dir value consumed by #fuzz (defaults to opts[:output])',
            output: 'optional - output value consumed by #fuzz',
            target: 'required - hostname, IP, or CIDR to scan',
            args: 'optional - Array args value consumed by #fuzz'
          )

          # Dedup AFL++ crash files by sha256 and note AddressSanitizer hits.
          #{self}.crash_triage(
            out_dir: 'required - AFL output directory containing crashes/',
            output: 'optional - alias for out_dir'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
