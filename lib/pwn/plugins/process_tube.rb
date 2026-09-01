# frozen_string_literal: true

require 'pty'
require 'timeout'
require 'socket'

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
        r, w, pid = PTY.spawn(*argv)
        id = "tube_#{pid}"
        @tubes[id] = { r: r, w: w, pid: pid, buf: +'' }
        { id: id, pid: pid }
      end

      public_class_method def self.connect(opts = {})
        host = (opts[:host] || opts[:target]).to_s
        port = opts[:port].to_i
        raise 'ERROR: host and port are required' if host.empty? || port <= 0

        sock = TCPSocket.new(host, port)
        id = "sock_#{sock.object_id}"
        @tubes[id] = { r: sock, w: sock, pid: nil, buf: +'' }
        { id: id, host: host, port: port }
      end

      public_class_method def self.write_line(opts = {})
        t = tube!(opts)
        line = opts[:line] || opts[:data] || ''
        t[:w].write("#{line}\n")
        t[:w].flush
        line.to_s
      end

      public_class_method def self.recvuntil(opts = {})
        t = tube!(opts)
        needle = opts[:until].to_s
        raise 'ERROR: until is required' if needle.empty?

        timeout = (opts[:timeout] || 5).to_f
        Timeout.timeout(timeout) do
          loop do
            return t[:buf] if t[:buf].include?(needle)

            ch = t[:r].read_nonblock(4_096)
            t[:buf] << ch
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
        t[:w].close
        t[:r].close
        Process.kill('TERM', t[:pid]) if t[:pid]
        @tubes.delete(opts[:id].to_s)
        true
      rescue StandardError
        @tubes.delete(opts[:id].to_s)
        false
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
            command: 'optional - command value consumed by #spawn'
          )

          # Connect a TCP tube with the same write_line/recvuntil API as spawn.
          #{self}.connect(
            host: 'required - hostname or IP address (defaults to opts[:target])',
            target: 'optional - hostname, IP, or CIDR to scan',
            port: 'required - TCP/UDP port number'
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

          # Close a session previously returned by #open.
          #{self}.close(
            id: 'optional - id value consumed by #close'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.tube!(opts = {})
        id = opts[:id].to_s
        t = @tubes[id]
        raise 'ERROR: id is required / unknown tube' unless t

        t
      end
    end
  end
end
