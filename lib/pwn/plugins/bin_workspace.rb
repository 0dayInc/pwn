# frozen_string_literal: true

require 'digest'
require 'json'
require 'fileutils'

module PWN
  module Plugins
    # Persistent per-binary analysis workspace keyed by sha256.
    module BinWorkspace
      ROOT = File.join(Dir.home, '.pwn', 'binws')

      public_class_method def self.for(opts = {})
        path = (opts[:path] || opts[:bin]).to_s
        raise 'ERROR: path is required' if path.empty?
        raise "ERROR: file not found: #{path}" unless File.file?(path)

        sha = Digest::SHA256.file(path).hexdigest
        dir = File.join(ROOT, sha)
        FileUtils.mkdir_p(dir)
        notes = File.join(dir, 'notes.json')
        File.write(notes, JSON.generate({})) unless File.file?(notes)
        { sha256: sha, dir: dir, path: path, notes: notes }
      end

      public_class_method def self.annotate(opts = {})
        ws = self.for(opts)
        store = JSON.parse(File.read(ws[:notes]), symbolize_names: true)
        addr = (opts[:addr] || opts[:address]).to_s
        raise 'ERROR: addr is required' if addr.empty?

        store[addr.to_sym] = {
          kind: (opts[:kind] || 'comment').to_s,
          text: opts[:text].to_s,
          name: opts[:name].to_s
        }
        File.write(ws[:notes], JSON.pretty_generate(store))
        store[addr.to_sym].merge(sha256: ws[:sha256])
      end

      public_class_method def self.notes(opts = {})
        path = (opts[:path] || opts[:bin]).to_s
        ws = self.for(path: path)
        JSON.parse(File.read(ws[:notes]), symbolize_names: true)
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Open or create ~/.pwn/binws/<sha256> for a binary.
          #{self}.for(
            path: 'required - filesystem path of the binary',
            bin: 'optional - alias for path'
          )

          # Record a rename, comment, or tag at an address.
          #{self}.annotate(
            path: 'required - filesystem path of the binary',
            addr: 'required - address or symbol',
            address: 'optional - alias for addr',
            kind: 'optional - comment|rename|tag (defaults to comment)',
            text: 'optional - annotation body',
            name: 'optional - renamed symbol'
          )

          # Return the annotation map for a binary workspace.
          #{self}.notes(
            path: 'required - filesystem path of the binary'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
