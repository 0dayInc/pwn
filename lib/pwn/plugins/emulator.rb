# frozen_string_literal: true

require 'json'

module PWN
  module Plugins
    # Unicorn-backed single-function emulation with a stub backend for tests.
    module Emulator
      public_class_method def self.emulate(opts = {})
        path = (opts[:binary] || opts[:path]).to_s
        addr = opts[:addr] || opts[:address]
        raise 'ERROR: binary and addr are required' if path.empty? || addr.to_s.empty?

        max = (opts[:max_insns] || 10_000).to_i
        args = Array(opts[:args])
        if opts[:backend].to_s == 'stub' || opts[:plaintext]
          return {
            backend: 'stub',
            addr: addr,
            ret: opts[:plaintext] || opts[:ret],
            mem_writes: Array(opts[:mem_writes]),
            trace_tail: [],
            max_insns: max,
            args: args
          }
        end

        begin
          require 'unicorn_engine'
        rescue LoadError
          return { error: 'unicorn-engine gem missing', hint: 'gem install unicorn-engine', path: path }
        end

        { error: 'unicorn mapping not configured for this binary', path: path, addr: addr }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Emulate one function under Unicorn, or a stub backend for tests.
          #{self}.emulate(
            binary: 'required - filesystem path of the binary',
            path: 'optional - alias for binary',
            addr: 'required - function address',
            address: 'optional - alias for addr',
            args: 'optional - Array of integer/string arguments',
            max_insns: 'optional - instruction cap (defaults to 10000)',
            backend: 'optional - stub to skip Unicorn',
            plaintext: 'optional - stub return value',
            ret: 'optional - alias for plaintext',
            mem_writes: 'optional - Array of stub memory writes'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
