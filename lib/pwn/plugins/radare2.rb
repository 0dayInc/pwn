# frozen_string_literal: true

require 'json'
require 'open3'
require 'securerandom'

module PWN
  module Plugins
    # Persistent r2pipe-style session: open/cmd/cmdj/close plus helpers.
    module Radare2
      @sessions = {}

      public_class_method def self.required_bins
        %w[r2]
      end

      # Supported Method Parameters::
      # session = PWN::Plugins::Radare2.open(
      #   path: 'required - filesystem path to the binary r2 should open'
      # )
      public_class_method def self.open(opts = {})
        PWN::Plugins::Doctor.require_bin!(name: 'r2')
        path = opts[:path].to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: binary not found: #{path}" unless File.file?(path)

        stdin, stdout, waiter = Open3.popen2('r2', '-q0', '-e', 'scr.color=0', path)
        sid = SecureRandom.hex(8)
        @sessions[sid] = { stdin: stdin, stdout: stdout, waiter: waiter, path: path }
        read_until_null(io: stdout)
        sid
      end

      # Supported Method Parameters::
      # text = PWN::Plugins::Radare2.cmd(
      #   session: 'required - session id returned by #open',
      #   cmd: 'required - r2 command to run; returns raw text (e.g. pdf @ main)'
      # )
      public_class_method def self.cmd(opts = {})
        sess = session!(opts)
        line = opts[:cmd].to_s
        raise 'ERROR: cmd is required' if line.empty?

        sess[:stdin].write("#{line}\n")
        sess[:stdin].flush
        read_until_null(io: sess[:stdout])
      end

      # Supported Method Parameters::
      # json = PWN::Plugins::Radare2.cmdj(
      #   session: 'required - session id returned by #open',
      #   cmd: 'required - r2 command; trailing j is added if missing and stdout is JSON.parse (e.g. afl or aflj)'
      # )
      public_class_method def self.cmdj(opts = {})
        raw = cmd(opts.merge(cmd: opts[:cmd].to_s.sub(/j?\z/, 'j')))
        JSON.parse(raw)
      rescue JSON::ParserError
        raw
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.close(
      #   session: 'required - session id returned by #open'
      # )
      public_class_method def self.close(opts = {})
        sess = session!(opts)
        sess[:stdin].write("q\n")
        sess[:stdin].close
        sess[:stdout].close
        @sessions.delete(opts[:session].to_s)
        true
      rescue StandardError
        @sessions.delete(opts[:session].to_s)
        false
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.functions(
      #   session: 'required - session id returned by #open'
      # )
      public_class_method def self.functions(opts = {})
        cmdj(opts.merge(cmd: 'aflj'))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.xrefs_to(
      #   session: 'required - session id returned by #open',
      #   addr: 'required - address or flag to list xrefs to (e.g. main or 0x401000)'
      # )
      public_class_method def self.xrefs_to(opts = {})
        addr = opts[:addr].to_s
        cmdj(opts.merge(cmd: "axtj #{addr}"))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.disasm(
      #   session: 'required - session id returned by #open',
      #   addr: 'required - address or flag to disassemble from',
      #   n: 'optional - instruction count (defaults to 32)'
      # )
      public_class_method def self.disasm(opts = {})
        addr = opts[:addr].to_s
        n = (opts[:n] || 32).to_i
        cmd(opts.merge(cmd: "pd #{n} @ #{addr}"))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.strings(
      #   session: 'required - session id returned by #open'
      # )
      public_class_method def self.strings(opts = {})
        cmdj(opts.merge(cmd: 'izj'))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.imports(
      #   session: 'required - session id returned by #open'
      # )
      public_class_method def self.imports(opts = {})
        cmdj(opts.merge(cmd: 'iij'))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.sections(
      #   session: 'required - session id returned by #open'
      # )
      public_class_method def self.sections(opts = {})
        cmdj(opts.merge(cmd: 'iSj'))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.binary_info(
      #   session: 'required - session id returned by #open'
      # )
      public_class_method def self.binary_info(opts = {})
        cmdj(opts.merge(cmd: 'iIj'))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.decompile(
      #   session: 'required - session id returned by #open',
      #   addr: 'required - address or flag to decompile (needs r2ghidra)'
      # )
      public_class_method def self.decompile(opts = {})
        addr = opts[:addr].to_s
        cmd(opts.merge(cmd: "pdg @ #{addr}"))
      rescue StandardError => e
        { error: "#{e.class}: #{e.message}", hint: 'r2ghidra plugin may be absent' }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Open the binary in r2 (-q0) and return a session id.
          #{self}.open(
            path: 'required - filesystem path to the binary r2 should open'
          )

          # Run a command and return raw text output.
          #{self}.cmd(
            session: 'required - session id returned by #open',
            cmd: 'required - r2 command to run; returns raw text (e.g. pdf @ main)'
          )

          # Run a command, request JSON, and parse the result.
          #{self}.cmdj(
            session: 'required - session id returned by #open',
            cmd: 'required - r2 command; trailing j is added if missing and stdout is JSON.parse (e.g. afl or aflj)'
          )

          # Close a session previously returned by #open.
          #{self}.close(
            session: 'required - session id returned by #open'
          )

          # List functions after analysis (aflj JSON).
          #{self}.functions(
            session: 'required - session id returned by #open'
          )

          # List xrefs to an address or flag (axtj JSON).
          #{self}.xrefs_to(
            session: 'required - session id returned by #open',
            addr: 'required - address or flag to list xrefs to (e.g. main or 0x401000)'
          )

          # Disassemble n instructions at addr (pd text).
          #{self}.disasm(
            session: 'required - session id returned by #open',
            addr: 'required - address or flag to disassemble from',
            n: 'optional - instruction count (defaults to 32)'
          )

          # List strings in the binary (izj JSON).
          #{self}.strings(
            session: 'required - session id returned by #open'
          )

          # List imported symbols (iij JSON).
          #{self}.imports(
            session: 'required - session id returned by #open'
          )

          # List sections / segments (iSj JSON).
          #{self}.sections(
            session: 'required - session id returned by #open'
          )

          # Print binary header info (iIj JSON).
          #{self}.binary_info(
            session: 'required - session id returned by #open'
          )

          # Decompile a function at addr via r2ghidra (pdg text).
          #{self}.decompile(
            session: 'required - session id returned by #open',
            addr: 'required - address or flag to decompile (needs r2ghidra)'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.session!(opts = {})
        sid = opts[:session].to_s
        sess = @sessions[sid]
        raise 'ERROR: session is required / unknown' unless sess

        sess
      end

      private_class_method def self.read_until_null(opts = {})
        io = opts[:io]
        buf = +''
        loop do
          ch = io.read(1)
          break if ch.nil? || ch == "\x00"

          buf << ch
        end
        buf
      end
    end
  end
end
