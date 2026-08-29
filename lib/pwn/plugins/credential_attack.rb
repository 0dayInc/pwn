# frozen_string_literal: true

require 'fileutils'
require 'open3'

module PWN
  module Plugins
    # hydra/john/hashcat wrappers and ~/.pwn/wordlists convention.
    module CredentialAttack
      WORDLISTS = File.join(Dir.home, '.pwn', 'wordlists')

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.wordlist_dir(opts = {})
        FileUtils.mkdir_p(WORDLISTS) if opts[:ensure] != false
        WORDLISTS
      end

      public_class_method def self.hydra(opts = {})
        PWN::Plugins::Doctor.require_bin!(name: 'hydra')
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
        PWN::Plugins::Doctor.require_bin!(name: 'john')
        hashfile = opts[:hashfile] || opts[:file]
        raise 'ERROR: hashfile is required' if hashfile.to_s.empty?

        stdout, stderr, status = Open3.capture3('john', hashfile.to_s)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.hashcat(opts = {})
        PWN::Plugins::Doctor.require_bin!(name: 'hashcat')
        hashfile = opts[:hashfile] || opts[:file]
        mode = (opts[:mode] || 0).to_i
        wordlist = opts[:wordlist] || File.join(WORDLISTS, 'rockyou.txt')
        stdout, stderr, status = Open3.capture3('hashcat', '-m', mode.to_s, hashfile.to_s, wordlist)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
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

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
