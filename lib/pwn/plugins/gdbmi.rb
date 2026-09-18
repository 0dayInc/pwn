# frozen_string_literal: true

require 'open3'
require 'securerandom'
require 'tempfile'

module PWN
  # Plugin namespace. GDBMi is a requested alias of GDBMI.
  module Plugins
    # gdb --interpreter=mi3 session: breakpoints, run with stdin, registers,
    # memory, backtraces, and structured run_to_crash reports for ExploitDev.
    module GDBMI
      @sessions = {}

      public_class_method def self.required_bins
        %w[gdb]
      end

      public_class_method def self.open(opts = {})
        binary = (opts[:binary] || opts[:bin]).to_s
        engine = engine(opts)
        argv = [engine, '--interpreter=mi3', '--quiet']
        argv << '--nh' unless pwndbg?(engine: engine)
        argv += ['--args', binary] unless binary.empty?
        stdin, stdout, waiter = Open3.popen2(*argv)
        sid = SecureRandom.hex(8)
        @sessions[sid] = { stdin: stdin, stdout: stdout, waiter: waiter, binary: binary, engine: engine,
                           interpreter: 'mi3', pwndbg: pwndbg?(engine: engine) }
        drain(session: sid)
        mi(session: sid, cmd: '-gdb-set pagination off')
        mi(session: sid, cmd: '-gdb-set confirm off')
        sid
      end

      public_class_method def self.session(opts = {})
        session!(opts)
      end

      public_class_method def self.close(opts = {})
        sess = session!(opts)
        begin
          sess[:stdin].puts('-gdb-exit')
          sess[:stdin].close
          sess[:stdout].close
        rescue StandardError
          nil
        end
        @sessions.delete((opts[:session] || opts[:id]).to_s)
        { closed: true }
      end

      public_class_method def self.break(opts = {})
        loc = location!(opts)
        parse_mi(raw: mi(opts.merge(cmd: "-break-insert #{loc}")))
      end

      public_class_method def self.run(opts = {})
        stdin = opts[:stdin]
        cmd = if stdin.nil?
                '-exec-run'
              else
                file = Tempfile.new(['pwn-gdb-stdin', '.bin'])
                file.binmode
                file.write(stdin.is_a?(String) ? stdin : stdin.to_s)
                file.flush
                session!(opts)[:stdin_file] = file
                "-interpreter-exec console \"run < #{file.path}\""
              end
        parse_mi(raw: mi(opts.merge(cmd: cmd)))
      end

      public_class_method def self.continue(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: '-exec-continue')))
      end

      public_class_method def self.registers(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: '-data-list-register-values x')))
      end

      public_class_method def self.read_mem(opts = {})
        addr = addr!(opts)
        n = Integer(opts[:len] || opts[:length] || 64)
        raise ArgumentError, 'len must be 1..65536' unless n.between?(1, 65_536)

        parse_mi(raw: mi(opts.merge(cmd: "-data-read-memory-bytes #{addr} #{n}")))
      end

      public_class_method def self.read_memory(opts = {})
        read_mem(opts)
      end

      public_class_method def self.backtrace(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: '-stack-list-frames')))
      end

      public_class_method def self.step(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: (opts[:into] ? '-exec-step' : '-exec-next'))))
      end

      public_class_method def self.checksec(opts = {})
        PWN::Plugins::GDB.mitigations(opts)
      end

      public_class_method def self.run_to_crash(opts = {})
        sid = opts[:session] || PWN::Plugins::GDBMI.open(opts)
        begin
          run(opts.merge(session: sid))
          regs = registers(session: sid)
          stack = backtrace(session: sid)
          fault = evaluate(session: sid, expr: '$_siginfo._sifields._sigfault.si_addr')
          stopped = regs[:stopped] || stack[:stopped] || {}
          pc = regs[:registers]['rip'] || regs[:registers]['eip'] || regs[:registers]['pc'] || stopped[:addr]
          signal = stopped[:signal] || 'SIGSEGV'
          fault_addr = fault || stopped[:addr]
          crash = {
            signal: signal,
            pc: pc,
            fault_addr: fault_addr,
            exploitability: classify(signal: signal, pc: pc),
            registers: regs[:registers],
            backtrace: stack[:frames],
            interpreter: 'mi3',
            session: sid
          }
          crash[:exploitdev] = PWN::Plugins::ExploitDev.from_crash(crash: crash, payload: opts[:stdin]) if opts[:stdin]
          crash
        ensure
          close(session: sid) unless opts[:session]
        end
      end

      public_class_method def self.mi(opts = {})
        cmd = opts[:cmd].to_s
        raise ArgumentError, 'cmd is required' if cmd.empty?

        sess = session!(opts)
        sess[:stdin].puts(cmd)
        sess[:stdin].flush
        drain(opts)
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Open gdb --interpreter=mi3 (pwndbg when pwndbg: true).
          #{self}.open(
            binary: 'optional - filesystem path of the binary to debug',
            bin: 'optional - alias for binary',
            pwndbg: 'optional - true to launch the pwndbg frontend when installed'
          )

          # Return session metadata for an open MI handle.
          #{self}.session(
            session: 'required - session id returned by #open',
            id: 'optional - alias for session'
          )

          # Close an MI session.
          #{self}.close(
            session: 'required - session id returned by #open',
            id: 'optional - alias for session'
          )

          # Insert a breakpoint (MI -break-insert).
          #{self}.break(
            location: 'required - symbol or address',
            addr: 'optional - alias for location',
            symbol: 'optional - alias for location',
            session: 'optional - session id returned by #open'
          )

          # Run the inferior, optionally feeding stdin from a temp file.
          #{self}.run(
            session: 'required - session id returned by #open',
            stdin: 'optional - bytes written to the inferior stdin'
          )

          # Continue until the next stop.
          #{self}.continue(
            session: 'required - session id returned by #open'
          )

          # Read registers via MI.
          #{self}.registers(
            session: 'required - session id returned by #open'
          )

          # Read memory bytes at addr.
          #{self}.read_mem(
            session: 'required - session id returned by #open',
            addr: 'required - address to read',
            address: 'optional - alias for addr',
            len: 'optional - byte count (defaults to 64)',
            length: 'optional - alias for len'
          )

          # Alias of read_mem.
          #{self}.read_memory(
            session: 'required - session id returned by #open',
            addr: 'required - address to read',
            address: 'optional - alias for addr',
            len: 'optional - byte count (defaults to 64)',
            length: 'optional - alias for len'
          )

          # Backtrace via MI -stack-list-frames.
          #{self}.backtrace(
            session: 'required - session id returned by #open'
          )

          # Step (into when into: true, otherwise next).
          #{self}.step(
            session: 'optional - session id returned by #open',
            into: 'optional - true to step into (defaults to next)'
          )

          # checksec / mitigations via GDB.mitigations.
          #{self}.checksec(
            binary: 'optional - filesystem path of the binary'
          )

          # Run until crash and return signal, pc, fault_addr, exploitability.
          #{self}.run_to_crash(
            binary: 'optional - filesystem path of the binary to debug',
            bin: 'optional - alias for binary',
            stdin: 'optional - crashing input bytes',
            session: 'optional - reuse an open session instead of opening one',
            pwndbg: 'optional - true to launch the pwndbg frontend when installed'
          )

          # Send a raw MI command and return the record text.
          #{self}.mi(
            cmd: 'required - MI command string',
            session: 'required - session id returned by #open'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.engine(opts = {})
        return 'pwndbg' if opts[:pwndbg] == true && PWN::Plugins::PreflightChecker.bin?(name: 'pwndbg')
        return 'gdb' if PWN::Plugins::PreflightChecker.bin?(name: 'gdb')
        return 'pwndbg' if opts[:pwndbg] != false && PWN::Plugins::PreflightChecker.bin?(name: 'pwndbg')

        PWN::Plugins::PreflightChecker.require_bin!(name: 'gdb')
      end

      private_class_method def self.pwndbg?(opts = {})
        opts[:engine].to_s.include?('pwndbg')
      end

      private_class_method def self.session!(opts = {})
        sid = (opts[:session] || opts[:id]).to_s
        sess = @sessions[sid]
        raise ArgumentError, 'session is required / unknown' unless sess

        sess.merge(session: sid)
      end

      private_class_method def self.drain(opts = {})
        sess = session!(opts)
        buf = +''
        loop do
          ch = sess[:stdout].read(1)
          break if ch.nil?

          buf << ch
          plain = buf.gsub(/\e\[[0-9;]*[A-Za-z]/, '')
          break if plain.match?(/\(gdb\)\s*\z/)
        end
        buf
      end

      private_class_method def self.location!(opts = {})
        loc = (opts[:location] || opts[:addr] || opts[:symbol]).to_s
        raise ArgumentError, 'location is required' if loc.empty?
        raise ArgumentError, 'invalid location' unless loc.match?(/\A(?:\*?0x[0-9a-fA-F]+|[A-Za-z_$.][A-Za-z0-9_$.@+-]*)\z/)

        loc
      end

      private_class_method def self.addr!(opts = {})
        addr = (opts[:addr] || opts[:address]).to_s
        raise ArgumentError, 'addr is required' if addr.empty?
        raise ArgumentError, 'invalid address' unless addr.match?(/\A(?:0x[0-9a-fA-F]+|[0-9]+|[A-Za-z_$.][A-Za-z0-9_$.@]*)\z/)

        addr
      end

      private_class_method def self.parse_mi(opts = {})
        raw = opts[:raw].to_s.gsub(/\e\[[0-9;]*[A-Za-z]/, '')
        regs = {}
        raw.scan(/name="([^"]+)",value="([^"]+)"/) { |name, val| regs[name] = val }
        frames = []
        raw.scan(/frame=\{([^}]+)\}/) do |body|
          frame = {}
          body.first.to_s.scan(/(\w+)="([^"]+)"/) { |key, val| frame[key.to_sym] = val }
          frames << frame unless frame.empty?
        end
        stopped = {}
        if (m = raw.match(/\*stopped,([^\n]+)/))
          rec = m[1]
          stopped[:signal] = rec[/signal-name="([^"]+)"/, 1]
          stopped[:reason] = rec[/reason="([^"]+)"/, 1]
          stopped[:addr] = rec[/addr="([^"]+)"/, 1]
        end
        mem = {}
        if (m = raw.match(/begin="([^"]+)"[^}]*contents="([^"]+)"/))
          mem = { addr: m[1], hex: m[2], bytes: [m[2]].pack('H*') }
        end
        {
          ok: raw.match?(/\^(?:done|running|exit)|\*stopped/),
          raw: raw,
          registers: regs,
          frames: frames,
          stopped: stopped,
          memory: mem,
          signal: stopped[:signal],
          pc: stopped[:addr] || regs['rip'] || regs['eip'] || regs['pc']
        }
      end

      private_class_method def self.evaluate(opts = {})
        raw = mi(session: opts[:session], cmd: "-data-evaluate-expression #{opts[:expr]}")
        raw[/value="([^"]+)"/, 1]
      rescue StandardError
        nil
      end

      private_class_method def self.classify(opts = {})
        pc = opts[:pc].to_s.sub(/\A0x/, '')
        bytes = [pc].pack('H*')
        return 'pc_control' if bytes.bytesize >= 4 && bytes.bytes.all? { |byte| byte.between?(0x20, 0x7e) }
        return 'exploitable' if opts[:signal].to_s.match?(/SEGV|ILL|BUS/)
        return 'abort' if opts[:signal].to_s.include?('ABRT')
        return 'none' if opts[:signal].to_s.empty?

        'unknown'
      rescue StandardError
        'unknown'
      end
    end

    GDBMi = GDBMI unless const_defined?(:GDBMi, false)
  end
end
