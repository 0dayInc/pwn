# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'digest'
require 'time'

module PWN
  module Plugins
    # ~/.pwn/artifacts/<session>/ loot index for session_recall.
    module ArtifactRegistry
      ROOT = File.join(Dir.home, '.pwn', 'artifacts')

      public_class_method def self.required_bins
        []
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
        path = opts[:path].to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        { path: path, sha256: Digest::SHA256.file(path).hexdigest, bytes: File.size(path), body: File.binread(path)[0, 65_536] }
      end

      public_class_method def self.read_page(opts = {})
        path = opts[:path].to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        offset = opts[:offset].to_i
        length = (opts[:length] || 4_096).to_i
        length = 4_096 if length <= 0
        mode = (opts[:mode] || 'text').to_s
        data = File.binread(path, length, offset).to_s
        case mode
        when 'hex'
          { path: path, offset: offset, bytes: data.bytesize, hex: data.unpack1('H*') }
        when 'base64'
          require 'base64'
          { path: path, offset: offset, bytes: data.bytesize, body: Base64.strict_encode64(data) }
        else
          { path: path, offset: offset, bytes: data.bytesize, body: data.force_encoding('UTF-8').scrub }
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
          f.puts(JSON.generate(sha256: sha, size: bytes.bytesize, tool: opts[:tool], session: opts[:session_id], kind: opts[:kind], created_at: Time.now.utc.iso8601, source_path: src, dest: dest))
        end
        { sha256: sha, path: dest, size: bytes.bytesize }
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
            path: 'required - filesystem path of a registered artifact'
          )

          # Page an artifact as text, hex, or base64 from an offset.
          #{self}.read_page(
            path: 'required - filesystem path of the artifact',
            offset: 'optional - byte offset (defaults to 0)',
            length: 'optional - byte count (defaults to 4096)',
            mode: 'optional - text, hex, or base64 (defaults to text)'
          )

          # Store bytes under artifacts/sha256/<h2>/<hash> and append manifest.jsonl.
          #{self}.put(
            bytes: 'optional - raw bytes to store',
            path: 'optional - filesystem path to read when bytes is omitted',
            tool: 'optional - tool name for provenance',
            session_id: 'optional - pwn-ai session id for provenance',
            kind: 'optional - artifact kind'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
