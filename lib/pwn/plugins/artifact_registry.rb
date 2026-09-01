# frozen_string_literal: true

require 'fileutils'
require 'json'
require 'digest'

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

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Run register and return its result
          #{self}.register(
            session_id: 'optional - session id value consumed by #register',
            path: 'required - filesystem path to read or write',
            kind: 'optional - kind value consumed by #register'
          )

          # Run list and return its result
          #{self}.list(
            session_id: 'optional - session id value consumed by #list'
          )

          # Read an artifact file and return sha256 plus a body cap.
          #{self}.get(
            path: 'required - filesystem path of a registered artifact'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
