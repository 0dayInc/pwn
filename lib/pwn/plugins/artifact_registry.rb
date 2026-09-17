# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'digest'
require 'time'
require 'base64'

module PWN
  module Plugins
    # ~/.pwn/artifacts/<session>/ loot index for session_recall.
    module ArtifactRegistry
      ROOT = File.join(Dir.home, '.pwn', 'artifacts')

      public_class_method def self.required_bins
        []
      end

      public_class_method def self.spill(opts = {})
        bytes = opts[:bytes]
        raise ArgumentError, 'bytes must be a String' unless bytes.is_a?(String)

        sid = opts.fetch(:session_id).to_s
        raise ArgumentError, 'invalid session_id' unless sid.match?(/\A[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}\z/)

        dir = File.join(ROOT, sid)
        [ROOT, dir].each do |directory|
          raise ArgumentError, 'artifact directory is a symlink' if File.symlink?(directory)

          FileUtils.mkdir_p(directory, mode: 0o700)
          File.chmod(0o700, directory)
        end
        sha = Digest::SHA256.hexdigest(bytes)
        handle = "#{sid}/#{sha[0, 8]}.bin"
        path = File.join(ROOT, handle)
        # Lock the private directory to serialize creation and collision checks.
        File.open(dir) do |lock|
          lock.flock(File::LOCK_EX)
          raise ArgumentError, 'artifact file is a symlink' if File.symlink?(path)

          if File.exist?(path)
            raise "ERROR: artifact handle collision: #{handle}" unless File.file?(path) && Digest::SHA256.file(path).hexdigest == sha

            File.chmod(0o600, path)
          else
            File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) { |file| file.write(bytes) }
          end
        end
        { handle: handle, path: path, sha256: sha, bytes: bytes.bytesize }
      end

      public_class_method def self.register(opts = {})
        sid = (opts[:session_id] || 'default').to_s
        src = opts[:path].to_s
        raise 'ERROR: path is required' if src.empty?
        raise "ERROR: file not found: #{src}" unless File.file?(src)

        dir = File.join(ROOT, sid)
        FileUtils.mkdir_p(dir)
        dest = File.join(dir, File.basename(src))
        FileUtils.cp(src, dest)
        meta = File.join(dir, 'index.jsonl')
        File.open(meta, 'a') { |f| f.puts(JSON.generate(path: dest, kind: opts[:kind], src: src, at: Time.now.utc.iso8601)) }
        dest
      end

      public_class_method def self.list(opts = {})
        sid = (opts[:session_id] || 'default').to_s
        meta = File.join(ROOT, sid, 'index.jsonl')
        return [] unless File.file?(meta)

        File.readlines(meta).filter_map do |ln|
          JSON.parse(ln, symbolize_names: true)
        rescue JSON::ParserError
          nil
        end
      end

      public_class_method def self.get(opts = {})
        sha = opts[:sha256].to_s
        unless sha.empty?
          dest = File.join(ROOT, 'sha256', sha[0, 2], sha)
          path = dest if File.file?(dest)
        end
        path ||= opts[:path].to_s
        raise 'ERROR: path is required' if path.to_s.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        { path: path, sha256: Digest::SHA256.file(path).hexdigest, bytes: File.size(path), body: File.binread(path, 65_536) }
      end

      public_class_method def self.read_page(opts = {})
        path = artifact_path(opts)
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        raise 'ERROR: sha256 mismatch' if opts[:sha256].to_s != '' && Digest::SHA256.file(path).hexdigest != opts[:sha256].to_s

        unless opts[:grep].to_s.empty?
          result = grep(opts.merge(regex: opts[:grep], ignore_case: true)).merge(grep: opts[:grep])
          result[:matches].each { |hit| hit[:text] = hit[:text].chomp if hit[:encoding] == 'UTF-8' }
          return result
        end

        offset = opts[:offset].to_i
        raise ArgumentError, 'offset must be nonnegative' if offset.negative?

        maximum = (opts[:max_length] || 2048).to_i.clamp(1, 65_536)
        length = (opts[:length] || maximum).to_i
        length = maximum if length <= 0
        length = [length, maximum].min
        mode = (opts[:mode] || 'text').to_s
        data = File.binread(path, length, offset).to_s
        encoded = encode_page(bytes: data, mode: mode)
        total = File.size(path)
        { handle: opts[:handle], path: path, offset: offset, bytes: data.bytesize, total_bytes: total, next_offset: offset + data.bytesize, eof: offset + data.bytesize >= total }.merge(encoded)
      end

      # Match complete binary lines so page boundaries never hide a match.
      # Bound returned previews separately from the regex input.
      public_class_method def self.grep(opts = {})
        path = artifact_path(opts)
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        offset = opts[:offset].to_i
        raise ArgumentError, 'offset must be nonnegative' if offset.negative?

        pattern = opts.fetch(:regex).to_s.b
        raise ArgumentError, 'regex exceeds 2048 bytes' if pattern.bytesize > 2048

        flags = Regexp::NOENCODING | (opts[:ignore_case] ? Regexp::IGNORECASE : 0)
        rx = Regexp.new(pattern, flags, timeout: 0.05)
        limit = (opts[:limit] || 50).to_i.clamp(1, 50)
        remaining = (opts[:max_bytes] || 2048).to_i.clamp(1, 2048)
        total = File.size(path)
        cursor = offset
        matches = []
        deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 0.25
        line = offset.zero? ? 1 : nil
        File.open(path, 'rb') do |file|
          file.seek([offset - 1, 0].max)
          midline = offset.positive? && file.read(1) != "\n"
          file.seek(offset)
          while cursor < total && cursor - offset < 1_048_576 && matches.length < limit && remaining.positive?
            break if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline

            fragment = file.gets("\n", (64 * 1024 * 1024) + 1)
            break unless fragment

            raise ArgumentError, "line at offset #{cursor} exceeds 64 MiB; inspect with artifact_read" if fragment.bytesize > 64 * 1024 * 1024

            match = rx.match(fragment)
            if match
              start = fragment.bytesize <= remaining ? 0 : [match.begin(0) - 16, 0].max
              preview = fragment.byteslice(start, remaining)
              encoded = encode_page(bytes: preview, mode: 'text')
              matches << { offset: cursor + match.begin(0), fragment_offset: cursor + start, bytes: preview.bytesize, line: line, text: encoded[:body], encoding: encoded[:encoding], continued: start + preview.bytesize < fragment.bytesize, starts_midline: midline || start.positive? }
              remaining -= preview.bytesize
            end
            cursor = file.pos
            line += 1 if line && fragment.end_with?("\n")
            midline = false
          end
        end
        { handle: opts[:handle], path: path, matches: matches, offset: offset, next_offset: cursor, total_bytes: total, scanned_bytes: cursor - offset, eof: cursor >= total, semantics: 'binary_lines' }
      end

      # Resolve an opaque handle without returning its potentially large body.
      public_class_method def self.resolve(opts = {})
        handle = opts[:handle]
        raise ArgumentError, 'artifact handle is required' unless handle.is_a?(String) && !handle.empty?

        expected = opts[:sha256]
        raise ArgumentError, 'expected sha256 must be 64 lowercase hex digits' if expected && (!expected.is_a?(String) || !expected.match?(/\A[0-9a-f]{64}\z/))

        path = artifact_path(handle: handle)
        raise ArgumentError, 'artifact handle must resolve to a readable file' unless File.file?(path) && File.readable?(path)

        sha = Digest::SHA256.file(path).hexdigest
        declared = handle.match?(/\A(?:sha256:)?[0-9a-f]{64}\z/) ? handle.delete_prefix('sha256:') : File.basename(handle, '.bin')
        raise ArgumentError, 'artifact handle digest mismatch' unless sha.start_with?(declared)

        raise ArgumentError, 'artifact sha256 mismatch' if expected && expected != sha

        { handle: handle, path: path, sha256: sha, size: File.size(path) }
      end

      private_class_method def self.artifact_path(opts = {})
        handle = opts[:handle]
        return (opts[:path] || opts[:ref]).to_s if handle.nil?

        if handle.is_a?(String) && handle.match?(/\A(?:sha256:)?[0-9a-f]{64}\z/)
          sha = handle.delete_prefix('sha256:')
          handle = "sha256/#{sha[0, 2]}/#{sha}"
        else
          raise ArgumentError, 'invalid artifact handle' unless handle.is_a?(String) && handle.match?(%r{\A[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}/[0-9a-f]{8}\.bin\z})
        end

        path = File.join(ROOT, handle)
        [ROOT, File.join(ROOT, handle.split('/').first), File.dirname(path), path].each do |entry|
          raise ArgumentError, 'artifact handle contains a symlink' if File.symlink?(entry)
        end
        path
      end

      private_class_method def self.encode_page(opts = {})
        data = opts[:bytes].dup.force_encoding(Encoding::UTF_8)
        mode = opts[:mode].to_s
        raise ArgumentError, 'mode must be text, hex, or base64' unless %w[text hex base64].include?(mode)

        mode = 'base64' if mode == 'text' && !data.valid_encoding?
        case mode
        when 'hex'
          body = data.unpack1('H*')
          { mode: mode, encoding: 'hex', body: body, hex: body }
        when 'base64'
          { mode: mode, encoding: 'base64', body: Base64.strict_encode64(data) }
        else
          { mode: mode, encoding: 'UTF-8', body: data }
        end
      end

      public_class_method def self.put(opts = {})
        bytes = opts[:bytes]
        src = opts[:path].to_s
        bytes = File.binread(src) if bytes.nil? && File.file?(src)
        raise 'ERROR: bytes or path is required' if bytes.nil?

        sha = Digest::SHA256.hexdigest(bytes)
        dir = File.join(ROOT, 'sha256', sha[0, 2])
        FileUtils.mkdir_p(dir)
        dest = File.join(dir, sha)
        File.binwrite(dest, bytes) unless File.file?(dest)
        meta = File.join(ROOT, 'manifest.jsonl')
        FileUtils.mkdir_p(ROOT)
        File.open(meta, 'a') do |f|
          f.flock(File::LOCK_EX)
          f.puts(JSON.generate(sha256: sha, size: bytes.bytesize, tool: opts[:tool], session: opts[:session_id], kind: opts[:kind], tags: Array(opts[:tags]), created_at: Time.now.utc.iso8601, source_path: src, dest: dest))
        end
        { handle: "sha256:#{sha}", sha256: sha, path: dest, size: bytes.bytesize, tags: Array(opts[:tags]) }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run register and return its result
          #{self}.register(
            session_id: 'optional - pwn-ai session id that produced this artifact',
            path: 'required - filesystem path to read or write',
            kind: 'optional - kind value consumed by #register'
          )

          # Run list and return its result
          #{self}.list(
            session_id: 'optional - pwn-ai session id whose artifacts to list'
          )

          # Read an artifact file and return sha256 plus a body cap.
          #{self}.get(
            path: 'required - filesystem path of a registered artifact',
            sha256: 'optional - content hash used when path is omitted'
          )

          # Store bytes under artifacts/sha256/<h2>/<hash> and append manifest.jsonl.
          #{self}.put(
            bytes: 'optional - raw bytes to store',
            path: 'optional - filesystem path to read when bytes is omitted',
            tool: 'optional - tool name for provenance',
            session_id: 'optional - pwn-ai session id for provenance',
            kind: 'optional - artifact kind',
            tags: 'optional - Array of short labels for this artifact'
          )

          # Resolve a handle to host-computed evidence metadata without loading its body.
          #{self}.resolve(
            handle: 'required - session/sha8.bin, sha256:fullhash, or legacy fullhash artifact handle',
            sha256: 'optional - expected full SHA-256 to validate against stored bytes'
          )

          # Spill exact bytes privately; returns handle, path, full sha256 and bytes.
          #{self}.spill(
            bytes: 'required - raw String bytes, never scrubbed or truncated',
            session_id: 'required - 1-128 ASCII letters/digits/underscore/dot/hyphen; first character cannot be dot'
          )

          # Search complete binary lines with first match per line and bounded previews.
          # Lines over 64 MiB raise an explicit error; inspect those with artifact_read.
          # Scan budget is 1 MiB between lines; a complete line may exceed that budget.
          # Regex timeout is 50ms (raises Regexp::TimeoutError); scan budget is 250ms.
          # Resume next_offset until eof, even with no matches. Newlines are retained.
          # Match offset is absolute bytes; preview starts at fragment_offset and may be base64.
          # continued marks a shortened preview; line is nil for nonzero start offsets.
          #{self}.grep(
            handle: 'optional - session/sha8.bin handle instead of path',
            path: 'optional - legacy file path when handle is omitted',
            ref: 'optional - alias for path',
            regex: 'required - binary regex source, at most 2048 bytes',
            offset: 'optional - nonnegative byte offset, default 0',
            limit: 'optional - matching lines per page, clamped to 1-50',
            max_bytes: 'optional - total raw preview bytes per page, clamped to 1-2048',
            ignore_case: 'optional - case insensitive matching, default false'
          )

          # Page exact artifact bytes; invalid UTF-8 pages automatically use base64.
          # Returns handle/path, offset, bytes, total_bytes, next_offset, eof, mode, encoding, body.
          # Follow next_offset until eof; hex also retains the legacy hex field.
          #{self}.read_page(
            handle: 'optional - session/sha8.bin handle instead of path',
            path: 'optional - filesystem path when handle is omitted',
            ref: 'optional - alias for path',
            offset: 'optional - byte offset (defaults to 0)',
            length: 'optional - byte count, capped at max_length (default 2048)',
            max_length: 'optional - configured page cap, clamped to 1-65536 bytes, default 2048',
            mode: 'optional - text, hex, or base64 (defaults to text)',
            grep: 'optional - legacy case-insensitive bounded line search instead of paging',
            sha256: 'optional - expected sha256 of the file'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
