# frozen_string_literal: true

require 'pty'
require 'timeout'
require 'socket'
require 'securerandom'
require 'open3'

module PWN
  module Plugins
    # PTY.spawn tube: sendline/recvuntil/recvline, persisted across pwn_eval.
    module ProcessTube
      @tubes = {}

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.spawn(opts = {})
        cmd = opts[:cmd] || opts[:command]
        raise 'ERROR: cmd is required' if cmd.to_s.empty?

        argv = cmd.is_a?(Array) ? cmd.map(&:to_s) : ['bash', '-lc', cmd.to_s]
        name = (opts[:name] || "tube_#{SecureRandom.hex(4)}").to_s
        if opts[:pty] == false
          stdin, stdout, waiter = Open3.popen2(*argv)
          stdin.binmode
          stdout.binmode
          @tubes[name] = { r: stdout, w: stdin, pid: waiter.pid, buf: +'', started_at: Time.now, last_io: Time.now, name: name, scrollback: +'', wait: waiter }
          return { id: name, pid: waiter.pid, name: name, pty: false }
        end

        r, w, pid = PTY.spawn(*argv)
        name = (opts[:name] || "tube_#{pid}").to_s
        @tubes[name] = { r: r, w: w, pid: pid, buf: +'', started_at: Time.now, last_io: Time.now, name: name, scrollback: +'' }
        { id: name, pid: pid, name: name, pty: true }
      end

      public_class_method def self.connect(opts = {})
        host = (opts[:host] || opts[:target]).to_s
        port = opts[:port].to_i
        raise 'ERROR: host and port are required' if host.empty? || port <= 0

        sock = TCPSocket.new(host, port)
        id = "sock_#{sock.object_id}"
        @tubes[id] = { r: sock, w: sock, pid: nil, buf: +'', scrollback: +'', started_at: Time.now, last_io: Time.now }
        { id: id, host: host, port: port }
      end

      public_class_method def self.send_line(opts = {})
        write_line(opts)
      end

      public_class_method def self.sendline(opts = {})
        write_line(opts)
      end

      public_class_method def self.recv(opts = {})
        t = tube!(opts)
        want = (opts[:n] || opts[:bytes] || 4_096).to_i
        timeout = (opts[:timeout] || 5).to_f
        Timeout.timeout(timeout) do
          loop do
            return consume_buf(tube: t, bytes: want) if t[:buf].bytesize >= want || (opts[:n].nil? && !t[:buf].empty? && !t[:r].wait_readable(0))

            ch = t[:r].read_nonblock(4_096)
            append_buf(tube: t, data: ch)
          rescue IO::WaitReadable
            t[:r].wait_readable(0.2)
            retry
          rescue EOFError
            return consume_buf(tube: t, bytes: t[:buf].bytesize)
          end
        end
      end

      public_class_method def self.write_line(opts = {})
        t = tube!(opts)
        line = opts[:line] || opts[:data] || ''
        t[:w].write("#{line}\n")
        t[:w].flush
        t[:last_io] = Time.now
        t[:scrollback] = (t[:scrollback].to_s + "#{line}\n")[-65_536, 65_536] || (t[:scrollback].to_s + "#{line}\n")
        line.to_s
      end

      public_class_method def self.recvuntil(opts = {})
        t = tube!(opts)
        needle = opts[:until].to_s
        raise 'ERROR: until is required' if needle.empty?

        timeout = (opts[:timeout] || 5).to_f
        Timeout.timeout(timeout) do
          loop do
            idx = t[:buf].index(needle)
            return consume_buf(tube: t, bytes: idx + needle.bytesize) if idx

            ch = t[:r].read_nonblock(4_096)
            append_buf(tube: t, data: ch)
          rescue IO::WaitReadable
            t[:r].wait_readable(0.2)
            retry
          end
        end
      end

      public_class_method def self.recvline(opts = {})
        recvuntil(opts.merge(until: "\n"))
      end

      public_class_method def self.close(opts = {})
        t = tube!(opts)
        dump_scrollback(tube: t, id: opts[:id] || opts[:name])
        t[:w].close
        t[:r].close
        Process.kill('TERM', t[:pid]) if t[:pid]
        @tubes.delete((opts[:id] || opts[:name]).to_s)
        true
      rescue StandardError
        @tubes.delete((opts[:id] || opts[:name]).to_s)
        false
      end

      public_class_method def self.send_raw(opts = {})
        t = tube!(opts)
        bytes = opts[:bytes] || opts[:data]
        raise ArgumentError, 'bytes is required' if bytes.nil?

        data = bytes.is_a?(String) ? bytes.b : Array(bytes).pack('C*')
        t[:w].write(data)
        t[:w].flush
        t[:last_io] = Time.now
        note_scrollback(tube: t, data: data)
        { written: data.bytesize, id: (opts[:id] || opts[:name]).to_s }
      end

      public_class_method def self.register(opts = {})
        io = opts[:io] || opts[:r]
        raise ArgumentError, 'io is required' unless io

        id = (opts[:id] || "sock_#{SecureRandom.hex(4)}").to_s
        @tubes[id] = { r: io, w: opts[:w] || io, pid: opts[:pid], buf: +'', scrollback: +'', started_at: Time.now, last_io: Time.now }
        { id: id }
      end

      public_class_method def self.expect(opts = {})
        t = tube!(opts)
        pattern = opts[:pattern] || opts[:until]
        raise ArgumentError, 'pattern is required' if pattern.nil? || pattern.to_s.empty?

        timeout = (opts[:timeout] || 5).to_f
        Timeout.timeout(timeout) do
          loop do
            hay = t[:buf].to_s
            hay = hay.gsub(/\e\[[0-9;]*[A-Za-z]/, '') if opts[:strip_ansi]
            if pattern.is_a?(Regexp)
              if (m = hay.match(pattern))
                consume_buf(tube: t, bytes: m.end(0))
                return { matched: m[0], offset: m.begin(0), id: (opts[:id] || opts[:name]).to_s }
              end
            elsif (idx = hay.index(pattern.to_s))
              take = consume_buf(tube: t, bytes: idx + pattern.to_s.bytesize)
              return { matched: take, offset: idx, id: (opts[:id] || opts[:name]).to_s }
            end
            ch = t[:r].read_nonblock(4_096)
            append_buf(tube: t, data: ch)
          rescue IO::WaitReadable
            t[:r].wait_readable(0.2)
            retry
          end
        end
      end

      public_class_method def self.stream(opts = {})
        t = tube!(opts)
        off = opts[:offset].to_i
        begin
          t[:buf] << t[:r].read_nonblock(4_096)
        rescue IO::WaitReadable, EOFError
          nil
        end
        data = t[:buf].to_s.byteslice(off..-1).to_s
        { data: data, offset: t[:buf].to_s.bytesize, id: opts[:id].to_s }
      end

      public_class_method def self.reap_orphans(opts = {})
        _sid = opts[:session_id]
        n = @tubes.length
        @tubes.each_key { |id| close(id: id) }
        @tubes.clear
        n
      end

      public_class_method def self.list(opts = {})
        _idle = opts[:idle]
        now = Time.now
        @tubes.map do |id, t|
          { id: id, pid: t[:pid], started_at: t[:started_at], last_io: t[:last_io], age_s: (now - (t[:started_at] || now)).to_i }
        end
      end

      public_class_method def self.kill(opts = {})
        id = opts[:id].to_s
        t = @tubes[id]
        return { ok: false, id: id } unless t

        Process.kill('TERM', t[:pid]) if t[:pid]
        close(id: id)
        { ok: true, id: id }
      rescue StandardError => e
        { ok: false, id: id, error: e.message }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run spawn and return its result
          #{self}.spawn(
            cmd: 'required - command string to run (defaults to opts[:command])',
            command: 'optional - command value consumed by #spawn',
            name: 'optional - persistent session name reused across tool calls',
            pty: 'optional - false uses pipes for binary IO (defaults to PTY)'
          )

          # Connect a TCP tube with the same write_line/recvuntil API as spawn.
          #{self}.connect(
            host: 'required - hostname or IP address (defaults to opts[:target])',
            target: 'optional - hostname, IP, or CIDR to scan',
            port: 'required - TCP/UDP port number'
          )

          # Expect-style alias of write_line.
          #{self}.send_line(
            id: 'required - tube id from spawn or connect',
            name: 'optional - alias for id',
            line: 'optional - line to write (newline appended)',
            data: 'optional - alias for line'
          )

          # Run write line and return its result
          #{self}.write_line(
            line: 'optional - line value consumed by #write_line',
            data: 'optional - data value consumed by #write_line'
          )

          # Run recvuntil and return its result
          #{self}.recvuntil(
            until: 'required - until value consumed by #recvuntil',
            timeout: 'optional - seconds to wait before giving up'
          )

          # Run recvline and return its result
          #{self}.recvline

          # pwntools-style alias of write_line.
          #{self}.sendline(
            id: 'required - tube id from spawn or connect',
            line: 'optional - line to write',
            data: 'optional - alias for line'
          )

          # Read up to n bytes from a tube.
          #{self}.recv(
            id: 'required - tube id from spawn or connect',
            n: 'optional - byte count (defaults to 4096)',
            bytes: 'optional - alias for n',
            timeout: 'optional - seconds to wait before giving up'
          )

          # Close a session previously returned by #open.
          #{self}.close(
            id: 'optional - id value consumed by #close'
          )

          # Expect a regex or substring, optionally stripping ANSI.
          #{self}.expect(
            id: 'required - tube id from spawn or connect',
            name: 'optional - alias for id',
            until: 'optional - substring to wait for',
            pattern: 'optional - regex or string to wait for',
            timeout: 'optional - seconds to wait before giving up',
            strip_ansi: 'optional - true removes CSI sequences before matching'
          )

          # Write raw bytes without appending a newline.
          #{self}.send_raw(
            id: 'required - tube id from spawn or connect',
            name: 'optional - alias for id',
            bytes: 'required - String or byte Array to write',
            data: 'optional - alias for bytes'
          )

          # Register an existing IO as a named tube.
          #{self}.register(
            io: 'required - readable/writable IO object',
            r: 'optional - alias for io',
            w: 'optional - write IO when split from r',
            id: 'optional - tube name to assign',
            pid: 'optional - associated process id'
          )

          # Tail the PTY buffer since a prior offset.
          #{self}.stream(
            id: 'required - tube id from spawn or connect',
            offset: 'optional - byte offset to start from (defaults to 0)'
          )

          # Close every open tube (session end / orphan GC).
          #{self}.reap_orphans(
            session_id: 'optional - agent session id for transcript grouping'
          )

          # List live tubes with age.
          #{self}.list(
            idle: 'optional - unused reserved idle-seconds filter'
          )

          # SIGTERM then close a tube by id.
          #{self}.kill(
            id: 'required - tube id from spawn or connect'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.tube!(opts = {})
        id = (opts[:id] || opts[:name]).to_s
        t = @tubes[id]
        raise 'ERROR: id is required / unknown tube' unless t

        t
      end

      BUF_MAX = 1_048_576

      private_class_method def self.append_buf(opts = {})
        t = opts[:tube]
        t[:buf] << opts[:data].to_s
        t[:buf].slice!(0, t[:buf].bytesize - BUF_MAX) if t[:buf].bytesize > BUF_MAX
        note_scrollback(tube: t, data: opts[:data])
        t[:buf]
      end

      private_class_method def self.consume_buf(opts = {})
        t = opts[:tube]
        n = opts[:bytes].to_i
        n = t[:buf].bytesize if n > t[:buf].bytesize
        t[:buf].slice!(0, n)
      end

      private_class_method def self.note_scrollback(opts = {})
        t = opts[:tube]
        return unless t

        t[:scrollback] = "#{t[:scrollback]}#{opts[:data]}"
        t[:scrollback].slice!(0, t[:scrollback].bytesize - BUF_MAX) if t[:scrollback].bytesize > BUF_MAX
      end

      private_class_method def self.dump_scrollback(opts = {})
        t = opts[:tube]
        return unless t

        body = t[:scrollback].to_s + t[:buf].to_s
        return if body.empty?
        return unless defined?(PWN::Plugins::ArtifactRegistry)

        PWN::Plugins::ArtifactRegistry.put(bytes: body, kind: 'pty-scrollback', tags: ['pty', opts[:id].to_s])
      rescue StandardError
        nil
      end
    end
  end
end
