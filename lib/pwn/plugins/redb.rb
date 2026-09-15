# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'sqlite3'
require 'open3'
require 'time'

module PWN
  module Plugins
    # Persistent per-binary analysis DB under ~/.pwn/redb.
    module REDB
      ROOT = File.join(Dir.home, '.pwn', 'redb')

      public_class_method def self.open(opts = {})
        bin = (opts[:bin] || opts[:path]).to_s
        raise ArgumentError, 'bin is required' if bin.empty?
        raise ArgumentError, "binary not found: #{bin}" unless File.file?(bin)

        sha = Digest::SHA256.file(bin).hexdigest
        dir = File.join(ROOT, sha)
        FileUtils.mkdir_p(dir)
        db_path = File.join(dir, 'analysis.sqlite')
        db = SQLite3::Database.new(db_path)
        db.results_as_hash = true
        migrate(db: db)
        analyze(db: db, bin: bin) if db.get_first_value("SELECT COUNT(*) FROM meta WHERE key = 'analyzed'").to_i.zero?
        { sha256: sha, dir: dir, db: db_path, bin: File.expand_path(bin) }
      ensure
        db&.close
      end

      public_class_method def self.funcs(opts = {})
        with_db(opts) { |db| db.execute('SELECT * FROM functions ORDER BY name') }
      end

      public_class_method def self.xrefs_to(opts = {})
        sym = (opts[:sym] || opts[:name] || opts[:addr]).to_s
        raise ArgumentError, 'sym is required' if sym.empty?

        with_db(opts) { |db| db.execute('SELECT * FROM xrefs WHERE dst = ?', [sym]) }
      end

      public_class_method def self.strings(opts = {})
        needle = opts[:match].to_s
        sql = 'SELECT * FROM strings'
        args = []
        unless needle.empty?
          sql += ' WHERE value LIKE ?'
          args << "%#{needle}%"
        end
        with_db(opts) { |db| db.execute(sql, args) }
      end

      public_class_method def self.decompile(opts = {})
        func = (opts[:func] || opts[:name]).to_s
        raise ArgumentError, 'func is required' if func.empty?

        with_db(opts) do |db|
          row = db.get_first_row('SELECT * FROM decompile WHERE name = ?', [func])
          return row if row

          text = objdump_func(bin: PWN::Plugins::REDB.open(opts)[:bin], func: func)
          db.execute('INSERT OR REPLACE INTO decompile(name, text, cached_at) VALUES(?,?,?)', [func, text, Time.now.utc.iso8601])
          { 'name' => func, 'text' => text }
        end
      end

      public_class_method def self.annotate(opts = {})
        note = opts[:text].to_s
        target = (opts[:addr] || opts[:func] || opts[:sym]).to_s
        raise ArgumentError, 'addr or func is required' if target.empty?

        with_db(opts) do |db|
          db.execute('INSERT INTO annotations(target, text, cached_at) VALUES(?,?,?)', [target, note, Time.now.utc.iso8601])
          { target: target, text: note }
        end
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Open or reuse ~/.pwn/redb/<sha256> for a binary.
          #{self}.open(
            bin: 'required - filesystem path of the binary',
            path: 'optional - alias for bin'
          )

          # List cached functions.
          #{self}.funcs(
            bin: 'required - filesystem path of the binary'
          )

          # Return callers of a symbol from cache.
          #{self}.xrefs_to(
            bin: 'required - filesystem path of the binary',
            sym: 'required - destination symbol or address',
            name: 'optional - alias for sym',
            addr: 'optional - alias for sym'
          )

          # Search cached strings.
          #{self}.strings(
            bin: 'required - filesystem path of the binary',
            match: 'optional - substring filter'
          )

          # Return cached decompilation, filling the cache from objdump on miss.
          #{self}.decompile(
            bin: 'required - filesystem path of the binary',
            func: 'required - function name',
            name: 'optional - alias for func'
          )

          # Persist an analyst annotation for a later session.
          #{self}.annotate(
            bin: 'required - filesystem path of the binary',
            addr: 'optional - address to annotate',
            func: 'optional - function name to annotate',
            sym: 'optional - symbol to annotate',
            text: 'optional - annotation body'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.migrate(opts = {})
        db = opts[:db]
        db.execute('CREATE TABLE IF NOT EXISTS functions(name TEXT PRIMARY KEY, addr TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS xrefs(src TEXT, dst TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS strings(value TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE IF NOT EXISTS imports(name TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE IF NOT EXISTS exports(name TEXT PRIMARY KEY)')
        db.execute('CREATE TABLE IF NOT EXISTS decompile(name TEXT PRIMARY KEY, text TEXT, cached_at TEXT, kind TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS annotations(target TEXT, text TEXT, cached_at TEXT)')
        db.execute('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)')
      end

      private_class_method def self.with_db(opts = {})
        meta = PWN::Plugins::REDB.open(opts)
        db = SQLite3::Database.new(meta[:db])
        db.results_as_hash = true
        yield db
      ensure
        db&.close
      end

      private_class_method def self.analyze(opts = {})
        db = opts[:db]
        bin = opts[:bin]
        analyze_binutils(db: db, bin: bin)
        db.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('analyzed', ?)", [Time.now.utc.iso8601])
      end

      private_class_method def self.analyze_r2(opts = {})
        analyze_binutils(opts)
      end

      private_class_method def self.analyze_binutils(opts = {})
        db = opts[:db]
        bin = opts[:bin]
        nm, = Open3.capture2('nm', '-C', bin)
        nm.each_line do |line|
          if (m = line.match(/\s+U\s+(\S+)/))
            db.execute('INSERT OR IGNORE INTO imports(name) VALUES(?)', [m[1]])
            next
          end
          next unless (m = line.match(/\A([0-9a-fA-F]+)\s+(\w)\s+(\S+)/))

          db.execute('INSERT OR REPLACE INTO functions(name, addr) VALUES(?,?)', [m[3], m[1]])
          db.execute('INSERT OR IGNORE INTO exports(name) VALUES(?)', [m[3]]) if m[2] == 'T'
        end
        dump, = Open3.capture2('objdump', '-d', bin)
        current = nil
        dump.each_line do |line|
          current = Regexp.last_match(1) if line =~ /<([^>]+)>:/
          next unless current && (line =~ /call\w*\s+.*<([^>@]+)/ || line =~ /call\w*\s+([A-Za-z_]\w*)(?:@plt)?/)

          db.execute('INSERT INTO xrefs(src, dst) VALUES(?,?)', [current, Regexp.last_match(1)])
        end
        strings, = Open3.capture2('strings', '-a', bin)
        strings.each_line { |s| db.execute('INSERT OR IGNORE INTO strings(value) VALUES(?)', [s.chomp]) }
      end

      private_class_method def self.objdump_func(opts = {})
        dump, = Open3.capture2('objdump', '-d', opts[:bin].to_s)
        keep = false
        rows = []
        dump.each_line do |line|
          if line =~ /<#{Regexp.escape(opts[:func].to_s)}>:/
            keep = true
            rows << line
            next
          end
          break if keep && line =~ /<[^>]+>:/

          rows << line if keep
        end
        rows.join
      end
    end
  end
end
