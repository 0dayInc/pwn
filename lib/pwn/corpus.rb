# frozen_string_literal: true

require 'fileutils'
require 'digest'
require 'json'
require 'net/http'
require 'uri'
require 'tmpdir'

module PWN
  # Named wordlist and payload corpora under ~/.pwn/corpora.
  module Corpus
    ROOT = File.join(Dir.home, '.pwn', 'corpora')
    INDEX = {
      subdomains_top1m: {
        url: 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt',
        sha256: nil
      },
      fuzz_short: {
        builtin: %w[A ' " < > ` ; | & ${IFS} ../]
      }
    }.freeze

    public_class_method def self.get(opts = {})
      opts = { name: opts } unless opts.is_a?(Hash)
      name = (opts[:name] || opts[:corpus] || opts[:key]).to_s.to_sym
      spec = INDEX[name]
      raise ArgumentError, "unknown corpus #{name}" unless spec

      FileUtils.mkdir_p(ROOT)
      path = File.join(ROOT, "#{name}.txt")
      if spec[:builtin]
        File.write(path, spec[:builtin].join("\n") << "\n") unless File.file?(path)
        return path
      end
      if File.file?(path)
        verify!(path: path, sha256: spec[:sha256])
        return path
      end
      offline = opts[:offline] == true || ENV['PWN_CORPUS_OFFLINE'] == '1'
      raise IOError, "corpus cache miss (offline): #{name}" if offline

      fetch(url: spec[:url], path: path, sha256: spec[:sha256])
      path
    end

    # Roll back caught publication errors while restore I/O remains possible.
    # This is not a two-file atomic commit: concurrent readers/writers and
    # process termination or power loss can observe an intermediate pair.
    # If rollback itself raises, retain the private recovery directory.
    public_class_method def self.update(opts = {})
      opts = { name: opts } unless opts.is_a?(Hash)
      name = (opts[:name] || opts[:corpus]).to_s.to_sym
      spec = INDEX[name]
      raise ArgumentError, "unknown corpus #{name}" unless spec
      raise ArgumentError, 'builtin corpora have no remote update' if spec[:builtin]

      path = File.join(ROOT, "#{name}.txt")
      FileUtils.mkdir_p(ROOT)
      directory = Dir.mktmpdir('.corpus-update-', ROOT)
      cleanup = true
      begin
        tmp = File.join(directory, 'download.tmp')
        fetch(url: spec[:url], path: tmp, sha256: spec[:sha256])
        backups = [path, "#{path}.sha256"].to_h do |destination|
          backup = File.join(directory, File.basename(destination))
          FileUtils.cp(destination, backup) if File.file?(destination)
          [destination, File.file?(backup) ? backup : nil]
        end
        begin
          FileUtils.mv(tmp, path)
          FileUtils.mv("#{tmp}.sha256", "#{path}.sha256")
        rescue StandardError
          cleanup = false
          backups.each do |destination, backup|
            backup ? File.rename(backup, destination) : FileUtils.rm_f(destination)
          end
          cleanup = true
          raise
        end
      ensure
        FileUtils.remove_entry(directory) if cleanup
      end
      path
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Resolve a named corpus to a local cache path.
        #{self}.get(
          name: 'required - corpus symbol such as subdomains_top1m or fuzz_short',
          corpus: 'optional - alias for name',
          key: 'optional - alias for name',
          offline: 'optional - true uses the cache only and raises on miss'
        )

        # Replace a remote corpus; caught publication errors restore the prior pair if rollback I/O succeeds.
        # Not power-loss/process-crash atomic or synchronized with concurrent readers/writers.
        # Failed rollback retains recovery files under ROOT/.corpus-update-* for manual recovery.
        #{self}.update(
          name: 'required - corpus symbol with a remote URL',
          corpus: 'optional - alias for name'
        )

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
    end

    private_class_method def self.verify!(opts = {})
      digest = Digest::SHA256.file(opts[:path]).hexdigest
      want = opts[:sha256].to_s
      want = File.read("#{opts[:path]}.sha256").to_s.strip if want.empty? && File.file?("#{opts[:path]}.sha256")
      raise IOError, 'corpus integrity mismatch' if !want.empty? && want != digest

      digest
    end

    private_class_method def self.fetch(opts = {})
      uri = URI.parse(opts[:url].to_s)
      body = Net::HTTP.get(uri)
      digest = Digest::SHA256.hexdigest(body)
      raise IOError, 'corpus integrity mismatch' if opts[:sha256] && !opts[:sha256].to_s.empty? && opts[:sha256] != digest

      FileUtils.mkdir_p(File.dirname(opts[:path]))
      File.write(opts[:path], body)
      File.write("#{opts[:path]}.sha256", digest)
      opts[:path]
    end
  end
end
