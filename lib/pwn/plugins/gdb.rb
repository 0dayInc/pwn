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

      public_class_method def self.crash_info(opts = {})
        binary = opts[:binary].to_s
        row = run_to_crash(opts.merge(binary: binary))
        out = "#{row[:stdout]}#{row[:stderr]}"
        sig = out[/Program received signal ([A-Z0-9]+)/, 1] || out[/SIG[A-Z]+/]
        pc = out[/\bpc\s+0x([0-9a-f]+)/i, 1] || out[/rip\s+0x([0-9a-f]+)/i, 1]
        frames = out.scan(/#\d+\s+0x[0-9a-f]+.+/).first(8)
        exploitability = if sig.to_s.include?('SEGV') && pc
                           'likely-exploitable'
                         elsif sig
                           'unknown'
                         end
        {
          signal: sig,
          pc: pc,
          faulting_access: out[/Access at address 0x([0-9a-f]+)/, 1],
          backtrace: frames,
          regs: out,
          exploitability_heuristic: exploitability,
          raw: row
        }
      end

      public_class_method def self.debug_session(opts = {})
        script = Array(opts[:script] || opts[:commands])
        crash_info(opts.merge(commands: script))
      end

      public_class_method def self.ptrace_preflight(opts = {})
        _target = opts[:target]
        scope = 0
        path = '/proc/sys/kernel/yama/ptrace_scope'
        scope = File.read(path).to_i if File.file?(path)
        {
          ptrace_scope: scope,
          attach_ok: scope.zero?,
          hint: scope.positive? ? 'spawn instead of attach' : 'ok'
        }
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

          # Parse a run-to-crash gdb session into typed crash_info.
          #{self}.crash_info(
            binary: 'required - crashing binary path',
            args: 'optional - Array of inferior argv',
            commands: 'optional - extra gdb commands'
          )

          # Alias of crash_info for the debug_session agent tool.
          #{self}.debug_session(
            binary: 'required - crashing binary path',
            args: 'optional - Array of inferior argv',
            script: 'optional - Array of gdb/MI commands'
          )

          # Probe yama ptrace_scope before gdb/frida attach.
          #{self}.ptrace_preflight(
            target: 'optional - pid or binary path being attached'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
