# frozen_string_literal: true

require 'securerandom'

module PWN
  module Plugins
    # Structured GDB/MI driver with a handle registry that survives pwn_eval.
    module Debugger
      @sessions = {}

      public_class_method def self.required_bins
        %w[gdb]
      end

      public_class_method def self.launch(opts = {})
        bin = (opts[:bin] || opts[:binary]).to_s
        raise ArgumentError, 'bin is required' if bin.empty?

        args = Array(opts[:args]).map(&:to_s)
        argv = ['gdb', '--interpreter=mi2', '--quiet', '--nx', '--args', bin, *args]
        tube = PWN::Plugins::ProcessTube.spawn(cmd: argv, name: opts[:handle])
        row = store_session(handle: tube[:id], tube: tube, bin: bin)
        drain_gdb(handle: row[:handle])
        mi(handle: row[:handle], cmd: '-gdb-set confirm off')
        mi(handle: row[:handle], cmd: '-gdb-set pagination off')
        mi(handle: row[:handle], cmd: '-exec-run') if opts[:run] == true
        row
      end

      public_class_method def self.attach(opts = {})
        if opts[:host] || opts[:port]
          host = (opts[:host] || '127.0.0.1').to_s
          port = (opts[:port] || 1234).to_i
          argv = ['gdb', '--interpreter=mi2', '--quiet', '--nx']
          tube = PWN::Plugins::ProcessTube.spawn(cmd: argv, name: opts[:handle])
          row = store_session(handle: tube[:id], tube: tube, gdbstub: "#{host}:#{port}")
          drain_gdb(handle: row[:handle])
          parse_mi(raw: mi(handle: row[:handle], cmd: "-target-select remote #{host}:#{port}"))
          return row
        end
        pid = opts[:pid].to_i
        raise ArgumentError, 'pid is required' unless pid.positive?

        argv = ['gdb', '--interpreter=mi2', '--quiet', '--nx', '-p', pid.to_s]
        tube = PWN::Plugins::ProcessTube.spawn(cmd: argv, name: opts[:handle])
        row = store_session(handle: tube[:id], tube: tube, pid: pid)
        drain_gdb(handle: row[:handle])
        row
      end

      public_class_method def self.run(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: '-exec-run')))
      end

      public_class_method def self.break(opts = {})
        loc = (opts[:addr_or_sym] || opts[:location] || opts[:addr] || opts[:symbol]).to_s
        raise ArgumentError, 'addr_or_sym is required' if loc.empty?

        parse_mi(raw: mi(opts.merge(cmd: "-break-insert #{loc}")))
      end

      public_class_method def self.continue(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: '-exec-continue')))
      end

      public_class_method def self.step(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: (opts[:into] ? '-exec-step' : '-exec-next'))))
      end

      public_class_method def self.read_mem(opts = {})
        addr = (opts[:addr] || opts[:address]).to_s
        raise ArgumentError, 'addr is required' if addr.empty?

        parse_mi(raw: mi(opts.merge(cmd: "-data-read-memory-bytes #{addr} #{(opts[:len] || opts[:length] || 64).to_i}")))
      end

      public_class_method def self.write_mem(opts = {})
        addr = (opts[:addr] || opts[:address]).to_s
        data = opts[:data] || opts[:bytes]
        raise ArgumentError, 'addr and data are required' if addr.empty? || data.nil?

        hex = data.is_a?(String) ? data.unpack1('H*') : Array(data).pack('C*').unpack1('H*')
        parse_mi(raw: mi(opts.merge(cmd: "-data-write-memory-bytes #{addr} #{hex}")))
      end

      public_class_method def self.regs(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: '-data-list-register-values x')))
      end

      public_class_method def self.backtrace(opts = {})
        parse_mi(raw: mi(opts.merge(cmd: '-stack-list-frames')))
      end

      public_class_method def self.checksec(opts = {})
        PWN::Plugins::GDB.mitigations(binary: opts[:bin] || opts[:binary] || session!(opts)[:bin])
      end

      public_class_method def self.cyclic(opts = {})
        PWN::Plugins::ExploitDev.cyclic(length: opts[:length] || opts[:n] || 200)
      end

      public_class_method def self.cyclic_find(opts = {})
        PWN::Plugins::ExploitDev.cyclic_find(value: opts[:value] || opts[:pattern], length: opts[:length] || 8_192)
      end

      public_class_method def self.to_pwntools_offsets(opts = {})
        { cyclic: cyclic(opts), offset: cyclic_find(opts) }
      end

      public_class_method def self.close(opts = {})
        handle = (opts[:handle] || opts[:id]).to_s
        sess = @sessions.delete(handle)
        PWN::Plugins::ProcessTube.close(id: handle) if sess
        { closed: handle }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Launch a binary under gdb MI and keep the handle in-process.
          #{self}.launch(
            bin: 'required - filesystem path of the binary to debug',
            binary: 'optional - alias for bin',
            args: 'optional - Array of argv strings after the binary',
            handle: 'optional - ProcessTube name for the session',
            run: 'optional - true issues -exec-run after gdb starts'
          )

          # Attach gdb MI to an existing pid or gdbstub.
          #{self}.attach(
            pid: 'optional - integer process id to attach',
            host: 'optional - gdbstub host for remote attach',
            port: 'optional - gdbstub TCP port',
            handle: 'optional - ProcessTube name for the session'
          )

          # Run the inferior (-exec-run).
          #{self}.run(
            handle: 'required - session handle from launch or attach'
          )

          # Insert a breakpoint at a symbol or address.
          #{self}.break(
            handle: 'required - session handle from launch or attach',
            addr_or_sym: 'required - symbol or address',
            location: 'optional - alias for addr_or_sym',
            addr: 'optional - alias for addr_or_sym',
            symbol: 'optional - alias for addr_or_sym'
          )

          # Continue execution until the next stop.
          #{self}.continue(
            handle: 'required - session handle from launch or attach'
          )

          # Step one instruction or source line.
          #{self}.step(
            handle: 'required - session handle from launch or attach',
            into: 'optional - true to step into rather than next'
          )

          # Read memory bytes at an address.
          #{self}.read_mem(
            handle: 'required - session handle from launch or attach',
            addr: 'required - address to read',
            address: 'optional - alias for addr',
            len: 'optional - byte count (defaults to 64)',
            length: 'optional - alias for len'
          )

          # Write raw bytes to inferior memory.
          #{self}.write_mem(
            handle: 'required - session handle from launch or attach',
            addr: 'required - address to write',
            address: 'optional - alias for addr',
            data: 'required - String or byte Array to write',
            bytes: 'optional - alias for data'
          )

          # Return register values as a parsed MI hash.
          #{self}.regs(
            handle: 'required - session handle from launch or attach'
          )

          # Return a parsed backtrace hash.
          #{self}.backtrace(
            handle: 'required - session handle from launch or attach'
          )

          # Return binary mitigations via GDB.mitigations.
          #{self}.checksec(
            handle: 'optional - session handle whose binary should be probed',
            bin: 'optional - filesystem path of the binary',
            binary: 'optional - alias for bin'
          )

          # Generate a cyclic de Bruijn pattern.
          #{self}.cyclic(
            length: 'optional - pattern length in bytes',
            n: 'optional - alias for length'
          )

          # Find the offset of a packed register value in a cyclic pattern.
          #{self}.cyclic_find(
            value: 'required - leaked register value or substring',
            pattern: 'optional - alias for value',
            length: 'optional - haystack length (defaults to 8192)'
          )

          # Return both a cyclic pattern and the recovered offset.
          #{self}.to_pwntools_offsets(
            value: 'optional - leaked register value for cyclic_find',
            length: 'optional - pattern length in bytes',
            n: 'optional - alias for length'
          )

          # Close a debugger session handle.
          #{self}.close(
            handle: 'required - session handle from launch or attach',
            id: 'optional - alias for handle'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.store_session(opts = {})
        handle = opts[:handle].to_s
        @sessions[handle] = { tube: opts[:tube], bin: opts[:bin], pid: opts[:pid] }
        { handle: handle, pid: opts[:tube][:pid], bin: opts[:bin] }
      end

      private_class_method def self.session!(opts = {})
        handle = (opts[:handle] || opts[:id]).to_s
        sess = @sessions[handle]
        raise ArgumentError, "unknown debugger handle #{handle}" unless sess

        sess.merge(handle: handle)
      end

      private_class_method def self.drain_gdb(opts = {})
        PWN::Plugins::ProcessTube.expect(id: opts[:handle], pattern: /\(gdb\)/, timeout: opts[:timeout] || 8)
      rescue StandardError
        nil
      end

      private_class_method def self.mi(opts = {})
        sess = session!(opts)
        PWN::Plugins::ProcessTube.write_line(id: sess[:handle], line: opts[:cmd].to_s)
        row = PWN::Plugins::ProcessTube.expect(
          id: sess[:handle],
          pattern: /^\^done|^\^error|^\^running|^\*stopped/m,
          timeout: opts[:timeout] || 8
        )
        row.is_a?(Hash) ? row[:matched].to_s : row.to_s
      end

      private_class_method def self.parse_mi(opts = {})
        raw = opts[:raw].to_s
        ok = raw.match?(/\^(?:done|running)|^\*stopped/m)
        regs = {}
        raw.scan(/name="([^"]+)",value="([^"]+)"/) { |name, val| regs[name] = val }
        raw.scan(/number="(\d+)",value="([^"]+)"/) { |num, val| regs[num] ||= val }
        mem = {}
        if (m = raw.match(/memory=\[\{[^}]*begin="([^"]+)"[^}]*contents="([^"]+)"/))
          mem = { addr: m[1], hex: m[2] }
        end
        bkpt = {}
        if (m = raw.match(/bkpt=\{([^}]+)\}/))
          m[1].scan(/(\w+)="([^"]+)"/) { |k, v| bkpt[k.to_sym] = v }
        end
        { ok: ok, raw: raw, records: raw.lines.map(&:chomp), registers: regs, memory: mem, bkpt: bkpt }
      end
    end
  end
end
