# frozen_string_literal: true

require 'fileutils'
require 'digest'
require 'json'
require 'net/http'
require 'uri'

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

    public_class_method def self.update(opts = {})
      opts = { name: opts } unless opts.is_a?(Hash)
      name = (opts[:name] || opts[:corpus]).to_s.to_sym
      spec = INDEX[name]
      raise ArgumentError, "unknown corpus #{name}" unless spec
      raise ArgumentError, 'builtin corpora have no remote update' if spec[:builtin]

      path = File.join(ROOT, "#{name}.txt")
      tmp = "#{path}.tmp"
      fetch(url: spec[:url], path: tmp, sha256: spec[:sha256])
      FileUtils.mv(tmp, path)
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

        # Replace a remotely pinned corpus from its source URL.
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
      File.write("#{opts[:path].sub(/\\.tmp\\z/, '')}.sha256", digest)
      File.write("#{opts[:path]}.sha256", digest)
      opts[:path]
    end
  end
end
