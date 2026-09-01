# frozen_string_literal: true

require 'open3'
require 'digest'
require 'json'

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

      public_class_method def self.parse_stats(opts = {})
        out_dir = (opts[:out_dir] || opts[:output]).to_s
        raise 'ERROR: out_dir is required' if out_dir.empty?

        path = File.join(out_dir, 'fuzzer_stats')
        path = File.join(out_dir, 'default', 'fuzzer_stats') unless File.file?(path)
        return {} unless File.file?(path)

        File.read(path).each_line.with_object({}) do |line, acc|
          key, val = line.split(':', 2)
          next if key.to_s.strip.empty?

          acc[key.strip.to_sym] = val.to_s.strip
        end
      end

      public_class_method def self.crash_triage(opts = {})
        out_dir = (opts[:out_dir] || opts[:output]).to_s
        raise 'ERROR: out_dir is required' if out_dir.empty?

        crashes = Dir[File.join(out_dir, '**/crashes/id:*')]
        hashes = crashes.map { |p| [p, Digest::SHA256.file(p).hexdigest] }
        rows = hashes.map do |path, sha|
          art = File.join(out_dir, "crash-#{sha[0, 12]}.json")
          File.write(art, JSON.generate(path: path, sha256: sha))
          { path: path, sha256: sha, artifact: art }
        end
        {
          crashes: crashes,
          unique: hashes.map(&:last).uniq,
          asan: crashes.any? { |p| File.binread(p).include?('AddressSanitizer') },
          artifacts: rows
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

          # Parse AFL fuzzer_stats (execs_per_sec, paths, crashes) from out_dir.
          #{self}.parse_stats(
            out_dir: 'required - AFL output directory containing fuzzer_stats',
            output: 'optional - alias for out_dir'
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
