# frozen_string_literal: true

require 'open3'
require 'fileutils'
require 'json'
require 'digest'

module PWN
  module Plugins
    # Headless Ghidra analyzeHeadless wrapper with r2 fallback.
    module Ghidra
      public_class_method def self.required_bins
        %w[analyzeHeadless]
      end

      public_class_method def self.analyze(opts = {})
        path = (opts[:bin] || opts[:path]).to_s
        raise 'ERROR: bin is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        if PWN::Plugins::PreflightChecker.bin?(name: 'analyzeHeadless')
          proj = opts[:project_dir].to_s
          proj = File.join(Dir.home, '.pwn', 'ghidra') if proj.empty?
          FileUtils.mkdir_p(proj)
          stdout, stderr, status = Open3.capture3('analyzeHeadless', proj, 'pwn', '-import', path, '-deleteProject')
          return { stdout: stdout, stderr: stderr, exit: status.exitstatus, engine: 'ghidra' }
        end

        return r2_fallback(path: path) if PWN::Plugins::PreflightChecker.bin?(name: 'r2')

        { error: 'analyzeHeadless missing', hint: 'install Ghidra or r2; pwn setup --profile re' }
      end

      public_class_method def self.decompile(opts = {})
        path = (opts[:bin] || opts[:path]).to_s
        raise 'ERROR: bin is required' if path.empty?

        sha = Digest::SHA256.file(path).hexdigest if File.file?(path)
        cache = File.join(Dir.home, '.pwn', 'cache', 'decompile', "#{sha}.json") if sha
        return JSON.parse(File.read(cache), symbolize_names: true).merge(cached: true) if cache && File.file?(cache)

        row = analyze(opts)
        fn = opts[:function].to_s
        row[:function] = fn unless fn.empty?
        FileUtils.mkdir_p(File.dirname(cache)) if cache
        File.write(cache, JSON.generate(row)) if cache
        row
      end

      private_class_method def self.r2_fallback(opts = {})
        path = opts[:path].to_s
        stdout, stderr, status = Open3.capture3('r2', '-q', '-c', 'aaa;s main;pdg', path)
        if stdout.to_s.strip.empty?
          stdout, stderr, status = Open3.capture3('r2', '-q', '-c', 'aaa;s main;pdc', path)
          return { stdout: stdout, stderr: stderr, exit: status.exitstatus, engine: 'r2-pdc' }
        end
        { stdout: stdout, stderr: stderr, exit: status.exitstatus, engine: 'r2' }
      rescue StandardError => e
        { error: e.message, engine: 'r2' }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run analyzeHeadless (or r2 pdg) against a binary.
          #{self}.analyze(
            bin: 'required - filesystem path of the binary',
            path: 'optional - alias for bin',
            project_dir: 'optional - Ghidra project directory under ~/.pwn/ghidra'
          )

          # Decompile a binary; same as #analyze when Ghidra/r2 is the engine.
          #{self}.decompile(
            bin: 'required - filesystem path of the binary',
            path: 'optional - alias for bin',
            project_dir: 'optional - Ghidra project directory',
            function: 'optional - function name to decompile instead of the whole program'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
