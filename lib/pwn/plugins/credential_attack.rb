# frozen_string_literal: true

require 'fileutils'
require 'open3'

module PWN
  module Plugins
    # hydra/john/hashcat wrappers and ~/.pwn/wordlists convention.
    module CredentialAttack
      WORDLISTS = File.join(Dir.home, '.pwn', 'wordlists')

      public_class_method def self.required_bins
        %w[hydra john hashcat medusa]
      end

      public_class_method def self.wordlist_dir(opts = {})
        FileUtils.mkdir_p(WORDLISTS) if opts[:ensure] != false
        WORDLISTS
      end

      public_class_method def self.hydra(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'hydra')
        target = opts[:target].to_s
        service = (opts[:service] || 'ssh').to_s
        user = opts[:user] || opts[:login]
        wordlist = opts[:wordlist] || File.join(WORDLISTS, 'rockyou.txt')
        extra = Array(opts[:extra])
        cmd = ['hydra', '-l', user.to_s, '-P', wordlist, '-t', (opts[:tasks] || 4).to_s]
        cmd += extra
        cmd += [target, service]
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.john(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'john')
        hashfile = opts[:hashfile] || opts[:file]
        raise 'ERROR: hashfile is required' if hashfile.to_s.empty?

        stdout, stderr, status = Open3.capture3('john', hashfile.to_s)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.hashcat(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'hashcat')
        hashfile = opts[:hashfile] || opts[:file]
        mode = (opts[:mode] || 0).to_i
        wordlist = opts[:wordlist] || File.join(WORDLISTS, 'rockyou.txt')
        stdout, stderr, status = Open3.capture3('hashcat', '-m', mode.to_s, hashfile.to_s, wordlist)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.medusa(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'medusa')
        target = opts[:target].to_s
        raise 'ERROR: target is required' if target.empty?

        cmd = ['medusa', '-h', target, '-u', (opts[:user] || 'root').to_s, '-P', (opts[:wordlist] || File.join(WORDLISTS, 'rockyou.txt')).to_s, '-M', (opts[:module] || 'ssh').to_s]
        stdout, stderr, status = Open3.capture3(*cmd)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.identify_hash(opts = {})
        sample = (opts[:hash] || opts[:sample]).to_s
        raise 'ERROR: hash is required' if sample.empty?

        if PWN::Plugins::PreflightChecker.bin?(name: 'hashid')
          stdout, = Open3.capture3('hashid', sample)
          return { hash: sample, tool: 'hashid', stdout: stdout }
        end

        kind = case sample
               when /\A\$2[aby]\$/ then 'bcrypt'
               when /\A[a-f0-9]{32}\z/i then 'md5'
               when /\A[a-f0-9]{40}\z/i then 'sha1'
               when /\A[a-f0-9]{64}\z/i then 'sha256'
               else 'unknown'
               end
        { hash: sample, kind: kind }
      end

      public_class_method def self.fetch_seclists(opts = {})
        dest = (opts[:dest] || File.join(WORDLISTS, 'SecLists')).to_s
        return dest if Dir.exist?(dest)

        FileUtils.mkdir_p(File.dirname(dest))
        url = opts[:url] || 'https://github.com/danielmiessler/SecLists.git'
        stdout, stderr, status = Open3.capture3('git', 'clone', '--depth', '1', url, dest)
        { dest: dest, stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run wordlist dir and return its result
          #{self}.wordlist_dir(
            ensure: 'optional - ensure value consumed by #wordlist_dir'
          )

          # Run hydra and return its result
          #{self}.hydra(
            target: 'optional - hostname, IP, or CIDR to scan',
            service: 'optional - service value consumed by #hydra',
            user: 'optional - user value consumed by #hydra (defaults to opts[:login])',
            login: 'optional - login value consumed by #hydra',
            wordlist: 'optional - wordlist value consumed by #hydra',
            extra: 'optional - Array extra value consumed by #hydra',
            tasks: 'optional - tasks value consumed by #hydra'
          )

          # Run john and return its result
          #{self}.john(
            hashfile: 'required - hashfile value consumed by #john (defaults to opts[:file])',
            file: 'required - filesystem path'
          )

          # Run hashcat and return its result
          #{self}.hashcat(
            hashfile: 'optional - hashfile value consumed by #hashcat (defaults to opts[:file])',
            file: 'optional - filesystem path',
            mode: 'optional - mode value consumed by #hashcat',
            wordlist: 'optional - wordlist value consumed by #hashcat'
          )

          # Run medusa against a host (lockout-aware: keep -t low).
          #{self}.medusa(
            target: 'required - hostname or IP',
            user: 'optional - username (defaults to root)',
            wordlist: 'optional - password list path',
            module: 'optional - medusa module name (defaults to ssh)'
          )

          # Guess a hash type from a sample (hashid if present, else length heuristics).
          #{self}.identify_hash(
            hash: 'required - hash string to identify',
            sample: 'optional - alias for hash'
          )

          # Clone SecLists into ~/.pwn/wordlists/SecLists when missing.
          #{self}.fetch_seclists(
            dest: 'optional - destination directory',
            url: 'optional - git URL (defaults to danielmiessler/SecLists)'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
