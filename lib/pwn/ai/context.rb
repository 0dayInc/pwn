# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'pwn/ai/context_ingestion'

module PWN
  module AI
    # Attach files, hexdumps, disassembly, and HTTP transcripts to model
    # context with auto-chunking. Oversize artifacts are summarized inline
    # and persisted under ~/.pwn/artifacts/<session_id>/ with SHA-256.
    module Context
      WINDOW = 32_768
      CHUNK = 8_192

      public_class_method def self.attach_file(opts = {})
        path = opts[:path].to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        range = opts[:range]
        data = if range.is_a?(Range)
                 File.binread(path, range.end - range.begin, range.begin).to_s
               else
                 File.binread(path)
               end
        persist_and_chunk(bytes: data, path: path, kind: 'file', session_id: opts[:session_id], mime: mime_of(path: path))
      end

      public_class_method def self.attach_hexdump(opts = {})
        path = opts[:path].to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        offset = opts[:offset].to_i
        length = (opts[:length] || 512).to_i
        length = 512 if length <= 0
        slice = File.binread(path, length, offset).to_s
        hex = slice.unpack1('H*')
        persist_and_chunk(bytes: hex, path: path, kind: 'hexdump', session_id: opts[:session_id], extra: { offset: offset, length: slice.bytesize })
      end

      public_class_method def self.attach_disasm(opts = {})
        path = opts[:path].to_s
        raise 'ERROR: path is required' if path.empty?

        fn = opts[:function].to_s
        text = if defined?(PWN::Plugins::Radare2) && File.file?(path)
                 sid = PWN::Plugins::Radare2.open(path: path)
                 addr = fn.empty? ? 'main' : fn
                 result = PWN::Plugins::Radare2.disasm(session: sid, addr: addr, n: 64)
                 result.is_a?(String) ? result : JSON.pretty_generate(result)
               else
                 File.binread(path).to_s[0, CHUNK]
               end
        persist_and_chunk(bytes: text.to_s, path: path, kind: 'disasm', session_id: opts[:session_id], extra: { function: fn })
      end

      public_class_method def self.attach_http_transcript(opts = {})
        src = opts[:har_or_raw] || opts[:har] || opts[:raw] || opts[:path]
        bytes = if src.to_s.empty?
                  raise 'ERROR: har_or_raw is required'
                elsif File.file?(src.to_s)
                  File.binread(src.to_s)
                else
                  src.to_s
                end
        persist_and_chunk(bytes: bytes, path: src.to_s, kind: 'http_transcript', session_id: opts[:session_id])
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Ingest evidence into the local embedding database; positional path alone uses defaults.
          #{self}.ingest(path: '/path/to/evidence', session_id: 'default')

          # Retrieve auditable source citations for a prompt.
          #{self}.retrieve(query: 'service of interest', session_id: 'default')

          # Attach a file (optionally a byte range) and chunk it for the model.
          #{self}.attach_file(
            path: 'required - filesystem path to attach',
            range: 'optional - Range of bytes to attach instead of the whole file',
            session_id: 'optional - pwn-ai session id for the artifact store'
          )

          # Attach a hexdump slice of a binary.
          #{self}.attach_hexdump(
            path: 'required - filesystem path of the binary',
            offset: 'optional - byte offset (defaults to 0)',
            length: 'optional - byte count (defaults to 512)',
            session_id: 'optional - pwn-ai session id for the artifact store'
          )

          # Attach disassembly of a function (r2 when present).
          #{self}.attach_disasm(
            path: 'required - filesystem path of the binary',
            function: 'optional - function or address (defaults to main)',
            session_id: 'optional - pwn-ai session id for the artifact store'
          )

          # Attach a HAR or raw HTTP transcript.
          #{self}.attach_http_transcript(
            har_or_raw: 'required - HAR/raw string or filesystem path',
            har: 'optional - alias for har_or_raw',
            raw: 'optional - alias for har_or_raw',
            path: 'optional - filesystem path of a HAR file',
            session_id: 'optional - pwn-ai session id for the artifact store'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.persist_and_chunk(opts = {})
        bytes = opts[:bytes].to_s
        mime = opts[:mime].to_s
        summary = if binary_mime?(mime: mime, bytes: bytes)
                    binary_summary(bytes: bytes, path: opts[:path])
                  else
                    bytes[0, WINDOW]
                  end
        stored = if defined?(PWN::Plugins::ArtifactRegistry)
                   PWN::Plugins::ArtifactRegistry.put(bytes: bytes, path: opts[:path], kind: opts[:kind], session_id: opts[:session_id])
                 else
                   sid = (opts[:session_id] || 'default').to_s
                   sha = Digest::SHA256.hexdigest(bytes)
                   dir = File.join(Dir.home, '.pwn', 'artifacts', sid)
                   FileUtils.mkdir_p(dir)
                   dest = File.join(dir, sha)
                   File.binwrite(dest, bytes)
                   { sha256: sha, path: dest, size: bytes.bytesize }
                 end
        body = summary.to_s
        body = PWN::AI::Router.summarize(text: body) if bytes.bytesize > WINDOW && defined?(PWN::AI::Router)
        chunks = []
        i = 0
        while i < body.bytesize
          chunks << body.byteslice(i, CHUNK)
          i += CHUNK
        end
        {
          sha256: stored[:sha256],
          path: stored[:path],
          size: bytes.bytesize,
          kind: opts[:kind],
          summarized: bytes.bytesize > WINDOW,
          chunks: chunks,
          extra: opts[:extra]
        }.merge(opts[:extra].is_a?(Hash) ? opts[:extra] : {})
      end

      private_class_method def self.mime_of(opts = {})
        path = opts[:path].to_s
        return 'application/octet-stream' unless File.file?(path)

        head = File.binread(path, 16).to_s
        return 'application/x-elf' if head.start_with?("\x7fELF")
        return 'application/x-mach-binary' if head.start_with?("\xCF\xFA\xED\xFE") || head.start_with?("\xCE\xFA\xED\xFE")
        return 'application/x-dosexec' if head.start_with?('MZ')
        return 'application/json' if path.end_with?('.json', '.har')
        return 'text/plain' if head.force_encoding('UTF-8').valid_encoding?

        'application/octet-stream'
      end

      private_class_method def self.binary_mime?(opts = {})
        mime = opts[:mime].to_s
        return true if mime.start_with?('application/x-') || mime == 'application/octet-stream'

        bytes = opts[:bytes].to_s
        bytes.encoding == Encoding::ASCII_8BIT && bytes.bytes.any? { |b| b < 9 || (b > 13 && b < 32) }
      end

      private_class_method def self.binary_summary(opts = {})
        bytes = opts[:bytes].to_s
        printable = bytes.gsub(/[^\x20-\x7e]/n, '').byteslice(0, 2_048)
        entropy = shannon(bytes: bytes.byteslice(0, 4_096))
        "strings=#{printable[0, 400]} entropy=#{entropy.round(2)} size=#{bytes.bytesize} path=#{opts[:path]}"
      end

      private_class_method def self.shannon(opts = {})
        data = opts[:bytes].to_s
        return 0.0 if data.empty?

        freq = Hash.new(0)
        data.each_byte { |b| freq[b] += 1 }
        n = data.bytesize.to_f
        freq.values.sum do |c|
          p = c / n
          p.positive? ? -p * Math.log2(p) : 0
        end
      end
    end
  end
end
