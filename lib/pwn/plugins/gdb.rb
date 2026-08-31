# frozen_string_literal: true

require 'open3'

module PWN
  module Plugins
    # gdb/MI batch driver: run-to-crash, registers, mitigations, core dumps.
    module GDB
      public_class_method def self.required_bins
        %w[gdb]
      end

      public_class_method def self.batch(opts = {})
        PWN::Plugins::PreflightChecker.require_bin!(name: 'gdb')
        binary = opts[:binary].to_s
        cmds = Array(opts[:commands] || opts[:cmds])
        args = Array(opts[:args])
        mi = ['gdb', '--batch', '--quiet']
        mi += ['-ex', 'set pagination off']
        cmds.each { |c| mi += ['-ex', c.to_s] }
        mi << '--args' if !binary.empty? || args.any?
        mi << binary unless binary.empty?
        mi.concat(args.map(&:to_s))
        stdout, stderr, status = Open3.capture3(*mi)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.run_to_crash(opts = {})
        cmds = ['run', 'bt', 'info registers']
        batch(opts.merge(commands: cmds))
      end

      public_class_method def self.registers(opts = {})
        batch(opts.merge(commands: ['info registers']))
      end

      public_class_method def self.mitigations(opts = {})
        batch(opts.merge(commands: ['checksec']))
      rescue StandardError
        path = opts[:binary].to_s
        return { error: 'gdb missing' } unless PWN::Plugins::PreflightChecker.bin?(name: 'gdb')

        { hint: 'pwndbg/gef checksec not loaded', binary: path }
      end

      public_class_method def self.core(opts = {})
        core = opts[:core].to_s
        binary = opts[:binary].to_s
        raise 'ERROR: core is required' if core.empty?

        PWN::Plugins::PreflightChecker.require_bin!(name: 'gdb')
        binary = opts[:binary].to_s
        argv = ['gdb', '--batch', '--quiet', '-c', core, '-ex', 'set pagination off', '-ex', 'bt', '-ex', 'info registers']
        argv << binary unless binary.empty?
        stdout, stderr, status = Open3.capture3(*argv)
        { stdout: stdout, stderr: stderr, exit: status.exitstatus }
      end

      public_class_method def self.breakpoints(opts = {})
        bps = Array(opts[:breakpoints] || opts[:bp])
        cmds = bps.map { |b| "break #{b}" } + Array(opts[:commands]) + %w[run bt]
        batch(opts.merge(commands: cmds))
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run batch and return its result
          #{self}.batch(
            binary: 'required - binary value consumed by #batch',
            commands: 'optional - commands value consumed by #batch',
            cmds: 'optional - cmds value consumed by #batch',
            args: 'required - Array args value consumed by #batch'
          )

          # Run run to crash and return its result
          #{self}.run_to_crash

          # Run registers and return its result
          #{self}.registers

          # Run mitigations and return its result
          #{self}.mitigations(
            binary: 'optional - binary value consumed by #mitigations'
          )

          # Run core and return its result
          #{self}.core(
            core: 'required - filesystem path to the core dump',
            binary: 'optional - matching binary for symbols'
          )

          # Plant breakpoints then run and dump a backtrace.
          #{self}.breakpoints(
            binary: 'optional - binary to debug',
            breakpoints: 'optional - Array of break specs (e.g. main or *0x401000)',
            bp: 'optional - alias for breakpoints',
            commands: 'optional - extra gdb commands after the breaks',
            args: 'optional - Array of inferior argv'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
