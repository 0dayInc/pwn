# frozen_string_literal: true

require 'json'
require 'open3'
require 'securerandom'
require 'digest'
require 'pwn/plugins/binary_analysis'

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
      #   bin: 'required - filesystem path to the binary (alias: path)',
      #   write: 'optional - open r2/rizin with -w so patch_bytes can mutate the file'
      # )
      public_class_method def self.open(opts = {})
        path = (opts[:bin] || opts[:path]).to_s
        raise ArgumentError, 'bin or path is required' if path.empty?
        raise "ERROR: binary not found: #{path}" unless File.file?(path)

        engine = engine(opts)
        sha = Digest::SHA256.file(path).hexdigest
        write = opts[:write] == true
        hit = @sessions.find { |_id, sess| sess[:path] == path && sess[:sha256] == sha && sess[:engine] == engine && sess[:write] == write }
        return hit[0] if hit

        argv = [engine, '-q0', '-e', 'scr.color=0']
        argv.insert(1, '-w') if write
        stdin, stdout, waiter = Open3.popen2({ 'R2_NOPLUGINS' => '1' }, *argv, path)
        sid = SecureRandom.hex(8)
        pid = waiter.pid if waiter.respond_to?(:pid)
        @sessions[sid] = { stdin: stdin, stdout: stdout, waiter: waiter, path: path, sha256: sha, pid: pid, engine: engine, write: write, aaa: false }
        read_until_null(io: stdout)
        cmd(session: sid, cmd: 'aaa')
        @sessions[sid][:aaa] = true
        sid
      end

      public_class_method def self.analyze(opts = {})
        sess = session!(opts)
        cmd(opts.merge(cmd: 'aaa'))
        sess[:aaa] = true
        functions(opts)
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
        line = opts[:cmd].to_s
        raise ArgumentError, 'cmd is required' if line.empty?

        verb, rest = line.split(/\s+/, 2)
        verb = "#{verb}j" unless verb.end_with?('j')
        raw = cmd(opts.merge(cmd: [verb, rest].compact.join(' ')))
        JSON.parse(raw)
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
        cmdj(opts.merge(cmd: "axtj #{addr!(opts)}"))
      end

      public_class_method def self.xrefs_from(opts = {})
        cmdj(opts.merge(cmd: "axfj #{addr!(opts)}"))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.disasm(
      #   session: 'required - session id returned by #open',
      #   addr: 'required - address or flag to disassemble from',
      #   n: 'optional - instruction count (defaults to 32)'
      # )
      public_class_method def self.disasm(opts = {})
        addr = addr!(opts)
        count = opts[:n] || opts[:len]
        if count.nil?
          cmdj(opts.merge(cmd: "pdfj @ #{addr}"))
        else
          n = Integer(count)
          raise ArgumentError, 'n must be 1..4096 instructions' unless n.between?(1, 4096)

          cmdj(opts.merge(cmd: "pdj #{n} @ #{addr}"))
        end
      end

      public_class_method def self.seek(opts = {})
        addr = addr!(opts)
        cmd(opts.merge(cmd: "s #{addr}"))
        raw = cmd(opts.merge(cmd: 's'))
        value = raw.to_s.strip
        { addr: value, offset: value.to_i(16) }
      end

      public_class_method def self.patch_bytes(opts = {})
        addr = addr!(opts)
        hex = opts[:hex].to_s.downcase.delete_prefix('0x')
        raise ArgumentError, 'hex must be nonempty even-length hex' unless hex.match?(/\A[0-9a-f]+\z/) && hex.length.even?

        sess = session!(opts)
        raise ArgumentError, 'open the session with write: true before patch_bytes' unless sess[:write]

        cmd(opts.merge(cmd: "wx #{hex} @ #{addr}"))
        cmdj(opts.merge(cmd: "pxj #{hex.length / 2} @ #{addr}"))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.strings(
      #   session: 'required - session id returned by #open'
      # )
      public_class_method def self.strings(opts = {})
        return analyze_all(opts).then { |result| result.merge(data: result[:strings]) } if opts[:path]

        cmdj(opts.merge(cmd: 'izj'))
      end

      # Supported Method Parameters::
      # PWN::Plugins::Radare2.imports(
      #   session: 'required - session id returned by #open'
      # )
      public_class_method def self.imports(opts = {})
        return analyze_all(opts).then { |result| result.merge(data: result[:imports]) } if opts[:path]

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
        cmd(opts.merge(cmd: "pdg @ #{addr!(opts)}"))
      rescue StandardError => e
        { error: "#{e.class}: #{e.message}", hint: 'r2ghidra plugin may be absent' }
      end

      # Normalized read-only entrypoint. Legacy session APIs retain their return shapes.
      public_class_method def self.analyze_all(opts = {})
        path = File.realpath(File.expand_path(opts[:path].to_s))
        return BinaryAnalysis.analyze(opts.merge(path: path)) if opts[:backend] == 'binutils' || !BinaryAnalysis.available?(name: 'r2')

        data = {}
        { functions: 'aflj', strings: 'izzj', imports: 'iij' }.each do |key, command|
          raw = BinaryAnalysis.run(argv: ['r2', '-2', '-NN', '-q', '-e', 'scr.color=0', '-c', "aaa;#{command}", path], timeout: opts.fetch(:timeout, 60))
          data[key] = JSON.parse(raw)
        end
        data.merge(backend: 'radare2', status: 'ok', risk_level: 'low', path: path, sha256: Digest::SHA256.file(path).hexdigest, warnings: [])
      rescue StandardError => e
        BinaryAnalysis.analyze(opts).tap { |result| result[:warnings] << "radare2: #{e.message}" }
      end

      public_class_method def self.list_functions(opts = {})
        analyze_all(opts).then { |result| result.merge(data: result[:functions]) }
      end

      public_class_method def self.disasm_function(opts = {})
        normalized_query(opts.merge(command: 'pdfj'))
      end

      public_class_method def self.xrefs(opts = {})
        normalized_query(opts.merge(command: 'axtj'))
      end

      private_class_method def self.normalized_query(opts = {})
        command = opts[:command]
        address = (opts[:function] || opts[:addr] || 'main').to_s
        raise ArgumentError, 'invalid function/address' unless address.match?(/\A[a-zA-Z0-9_.$:]+\z/)

        path = File.realpath(File.expand_path(opts[:path].to_s))
        if opts[:backend] != 'binutils' && BinaryAnalysis.available?(name: 'r2')
          raw = BinaryAnalysis.run(argv: ['r2', '-2', '-NN', '-q', '-e', 'scr.color=0', '-c', "aaa;#{command} @ #{address}", path], timeout: opts.fetch(:timeout, 60))
          return { backend: 'radare2', status: 'ok', risk_level: 'low', data: JSON.parse(raw), path: path }
        end
        result = BinaryAnalysis.analyze(opts)
        data = if command == 'pdfj'
                 selector = address.match?(/\A(?:0x[0-9a-fA-F]+|[0-9]+)\z/) ? "--start-address=#{address}" : "--disassemble=#{address}"
                 BinaryAnalysis.run(argv: ['objdump', '-d', selector, path], timeout: opts.fetch(:timeout, 60))
               else
                 []
               end
        result.delete(:disassembly)
        result.merge(data: data, requested_function: address)
      rescue StandardError => e
        raise if e.is_a?(ArgumentError)

        BinaryAnalysis.analyze(opts).merge(data: [], error: e.message)
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Open the binary in r2/rizin (-q0) and return a session id.
          #{self}.open(
            bin: 'required - filesystem path to the binary r2 or rizin should open',
            path: 'optional - alias for bin',
            write: 'optional - true opens with -w so patch_bytes can persist mutations',
            backend: 'optional - r2 or rizin; default is r2 then rizin'
          )

          # Run aaa and return parsed aflj JSON.
          #{self}.analyze(
            session: 'required - session id returned by #open'
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

          # List xrefs from an address or flag (axfj JSON).
          #{self}.xrefs_from(
            session: 'required - session id returned by #open',
            addr: 'required - address or flag to list xrefs from'
          )

          # Disassemble a function (pdfj) or n instructions (pdj) as parsed JSON.
          #{self}.disasm(
            session: 'required - session id returned by #open',
            addr: 'required - address or flag; symbols, decimal, and 0x hex only',
            n: 'optional - instruction count for pdj; omit for pdfj of the function',
            len: 'optional - alias for n'
          )

          # Seek and return the current offset as JSON.
          #{self}.seek(
            session: 'required - session id returned by #open',
            addr: 'required - address or flag to seek to'
          )

          # Write hex bytes at addr (wx) and return parsed pxj of the written span.
          #{self}.patch_bytes(
            session: 'required - session id returned by #open',
            addr: 'required - address or flag to patch',
            hex: 'required - even-length hex string'
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
          # Invoke required_bins with the documented options; normalized path APIs report their backend.
          #{self}.required_bins
          # Invoke open with the documented options; normalized path APIs report their backend.
          #{self}.open(
            bin: 'optional - filesystem path to the local artifact or binary',
            path: 'optional - filesystem path to the local artifact or binary',
            write: 'optional - true opens the r2pipe session read/write',
            backend: 'optional - analysis backend name; binutils forces lightweight fallback'
          )
          # Invoke cmd with the documented options; normalized path APIs report their backend.
          #{self}.cmd(
            cmd: 'optional - raw radare2 command for the legacy session interface'
          )
          # Invoke cmdj with the documented options; normalized path APIs report their backend.
          #{self}.cmdj(
            cmd: 'optional - raw radare2 command for the legacy session interface'
          )
          # Invoke close with the documented options; normalized path APIs report their backend.
          #{self}.close(
            session: 'optional - session identifier returned by Radare2.open'
          )
          # Invoke functions with the documented options; normalized path APIs report their backend.
          #{self}.functions
          # Run aaa and return parsed aflj JSON.
          #{self}.analyze(
            session: 'optional - session identifier returned by Radare2.open'
          )
          # Seek and return the current offset as JSON.
          #{self}.seek(
            session: 'optional - session identifier returned by Radare2.open',
            addr: 'optional - hexadecimal address or binary symbol name'
          )
          # Write hex bytes at addr (wx) and return parsed pxj of the written span.
          #{self}.patch_bytes(
            session: 'optional - session identifier returned by Radare2.open',
            addr: 'optional - hexadecimal address or binary symbol name',
            hex: 'optional - even-length hex string to write'
          )
          # Invoke xrefs_to with the documented options; normalized path APIs report their backend.
          #{self}.xrefs_to(
            addr: 'optional - hexadecimal address or binary symbol name'
          )
          # Invoke xrefs_from with the documented options; normalized path APIs report their backend.
          #{self}.xrefs_from(
            addr: 'optional - hexadecimal address or binary symbol name'
          )
          # Invoke disasm with the documented options; normalized path APIs report their backend.
          #{self}.disasm(
            addr: 'optional - hexadecimal address or binary symbol name',
            len: 'optional - alternative maximum disassembly instruction count',
            n: 'optional - maximum disassembly instruction count; defaults to 32'
          )
          # Invoke strings with the documented options; normalized path APIs report their backend.
          #{self}.strings(
            path: 'optional - filesystem path to the local artifact or binary'
          )
          # Invoke imports with the documented options; normalized path APIs report their backend.
          #{self}.imports(
            path: 'optional - filesystem path to the local artifact or binary'
          )
          # Invoke sections with the documented options; normalized path APIs report their backend.
          #{self}.sections
          # Invoke binary_info with the documented options; normalized path APIs report their backend.
          #{self}.binary_info
          # Invoke decompile with the documented options; normalized path APIs report their backend.
          #{self}.decompile(
            addr: 'optional - hexadecimal address or binary symbol name'
          )
          # Invoke analyze_all with the documented options; normalized path APIs report their backend.
          #{self}.analyze_all(
            backend: 'optional - analysis backend name; binutils forces lightweight fallback',
            path: 'optional - filesystem path to the local artifact or binary',
            timeout: 'optional - positive subprocess or HTTP deadline in seconds'
          )
          # Invoke list_functions with the documented options; normalized path APIs report their backend.
          #{self}.list_functions
          # Invoke disasm_function with the documented options; normalized path APIs report their backend.
          #{self}.disasm_function
          # Invoke xrefs with the documented options; normalized path APIs report their backend.
          #{self}.xrefs
          # Invoke authors with the documented options; normalized path APIs report their backend.
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

      private_class_method def self.engine(opts = {})
        wanted = opts[:backend].to_s
        return wanted if %w[r2 rizin].include?(wanted) && PWN::Plugins::PreflightChecker.bin?(name: wanted)
        return 'r2' if PWN::Plugins::PreflightChecker.bin?(name: 'r2')
        return 'rizin' if PWN::Plugins::PreflightChecker.bin?(name: 'rizin')

        PWN::Plugins::PreflightChecker.require_bin!(name: 'r2')
      end

      private_class_method def self.addr!(opts = {})
        addr = opts[:addr].to_s
        raise ArgumentError, 'addr is required' if addr.empty?
        raise ArgumentError, 'invalid address' unless addr.match?(/\A(?:0x[0-9a-fA-F]+|[0-9]+|[A-Za-z_$.][A-Za-z0-9_$.@]*)\z/)

        addr
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
