# frozen_string_literal: true

require 'sqlite3'
require 'net/http'
require 'rexml/document'
require 'rexml/parsers/pullparser'
require 'base64'

module PWN
  module AI
    # Local evidence ingestion; XML is bounded to 100 element levels before XPath. Unavailable embeddings never become synthetic vectors.
    module Context
      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.ingest(opts = {})
        opts = { path: opts } unless opts.is_a?(Hash)
        path = opts[:path]
        source = File.realpath(File.expand_path(path.to_s))
        records = ingestion_records(opts.merge(source: source))
        db, warnings = ingestion_db(opts)
        warnings.concat(records.filter_map { |row| row[:text].lines.first&.strip if row[:text].start_with?('DEGRADED') })
        count = 0
        embedding_error = nil
        db.transaction do
          prefix = "#{source}/"
          db.execute('DELETE FROM chunks WHERE source = ? OR substr(source,1,?) = ?', [source, prefix.length, prefix])
          records.group_by { |row| row[:source] }.each_value do |rows|
            rows.each do |row|
              file = row[:source]
              row[:text].encode('UTF-8', invalid: :replace, undef: :replace).scan(/.{1,2048}/m).each_with_index do |text, index|
                vector, error = embedding_error ? [nil, embedding_error] : ingestion_embedding(opts.merge(text: text))
                embedding_error = error if error
                warnings << error if error
                citation = "#{file}##{row[:locator]}:chunk-#{index + 1}"
                db.execute('INSERT INTO chunks(source,sha256,locator,text,vector,model) VALUES(?,?,?,?,?,?)', [file, row[:sha256], citation, text, vector && JSON.generate(vector), opts[:model] || 'nomic-embed-text'])
                count += 1
              end
            end
          end
        end
        { status: warnings.empty? ? 'ok' : 'degraded', chunks: count, warnings: warnings.uniq, database: ingestion_db_path(opts) }
      ensure
        db&.close
      end

      public_class_method def self.retrieve(opts = {})
        opts = { query: opts } unless opts.is_a?(Hash)
        query = opts[:query]
        db, warnings = ingestion_db(opts)
        vector, error = ingestion_embedding(opts.merge(text: query.to_s))
        warnings << error if error
        semantic = vector && warnings.empty?
        terms = query.to_s.downcase.scan(/[[:alnum:]_]+/).uniq
        rows = db.execute('SELECT source,sha256,locator,text,vector,model FROM chunks')
        if semantic && rows.any? { |row| row[4].nil? || row[5] != (opts[:model] || 'nomic-embed-text') }
          semantic = false
          warnings << 'stored embeddings missing or model mismatch; using lexical retrieval'
        end
        hits = rows.filter_map do |row|
          source, sha, citation, text, stored, model = row
          score = if semantic && stored && model == (opts[:model] || 'nomic-embed-text')
                    candidate = JSON.parse(stored)
                    next unless candidate.length == vector.length

                    db.get_first_value('SELECT vec_distance_cosine(?, ?)', [JSON.generate(vector), stored]).to_f.then { |distance| 1.0 - distance }
                  else
                    next if semantic

                    terms.sum { |term| text.downcase.scan(Regexp.new(Regexp.escape(term))).length }.to_f
                  end
          next if !semantic && !score.positive?

          { source: source, sha256: sha, citation: citation, text: text, score: score }
        end
        hits = hits.sort_by { |row| -row[:score] }.first(opts.fetch(:top_k, 5).to_i.clamp(1, 50))
        { status: semantic ? 'ok' : 'degraded', backend: semantic ? 'sqlite-vec' : 'sqlite-lexical', warnings: warnings.uniq, chunks: hits, context: hits.map { |row| "[#{row[:citation]} sha256=#{row[:sha256]}]\n#{row[:text]}" }.join("\n\n") }
      ensure
        db&.close
      end

      public_class_method def self.help
        puts "USAGE:
          # Display module authors.
          #{self}.authors

          # Ingest local evidence into the session sqlite database with real local embeddings or explicit lexical degradation.
          #{self}.ingest(
            model: 'optional - installed Ollama embedding model name; defaults to nomic-embed-text',
            path: 'required - filesystem path to the local artifact or binary'
          )

          # Retrieve top-k chunks with source citations from the session evidence database.
          #{self}.retrieve(
            model: 'optional - installed Ollama embedding model name; defaults to nomic-embed-text',
            query: 'required - prompt text used to retrieve matching evidence chunks',
            top_k: 'optional - maximum retrieved chunks; clamped to 1 through 50'
          )
        "
        constants.sort
      end

      private_class_method def self.ingestion_db_path(opts = {})
        session = opts.fetch(:session_id, 'default').to_s
        raise ArgumentError, 'invalid session_id' unless session.match?(/\A[\w.-]+\z/) && !%w[. ..].include?(session)

        File.join(File.expand_path(opts[:root] || '~/.pwn/embeddings'), "#{session}.db")
      end

      private_class_method def self.ingestion_db(opts = {})
        path = ingestion_db_path(opts)
        FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
        db = SQLite3::Database.new(path)
        File.chmod(0o600, path)
        db.busy_timeout = 5000
        db.execute('CREATE TABLE IF NOT EXISTS chunks(id INTEGER PRIMARY KEY,source TEXT,sha256 TEXT,locator TEXT,text TEXT,vector TEXT,model TEXT)')
        warnings = []
        begin
          db.enable_load_extension(true)
          extension = opts[:vec_extension] || ENV.fetch('PWN_SQLITE_VEC_EXTENSION', nil)
          if extension
            db.load_extension(File.expand_path(extension))
          else
            require 'sqlite_vec'
            SqliteVec.load(db)
          end
          db.get_first_value('SELECT vec_version()')
        rescue LoadError, StandardError => e
          warnings << "sqlite-vec unavailable: #{e.class}: #{e.message}"
        ensure
          db.enable_load_extension(false)
        end
        [db, warnings]
      end

      private_class_method def self.ingestion_embedding(opts = {})
        text = opts[:text]
        uri = URI("#{opts.fetch(:endpoint, 'http://127.0.0.1:11434').to_s.sub(%r{/$}, '')}/api/embed")
        raise ArgumentError, 'embeddings endpoint must be local HTTP' unless %w[127.0.0.1 localhost ::1].include?(uri.host) && %w[http https].include?(uri.scheme)

        http = Net::HTTP.new(uri.host, uri.port, nil)
        http.use_ssl = uri.scheme == 'https'
        http.open_timeout = opts.fetch(:timeout, 5)
        http.read_timeout = opts.fetch(:timeout, 30)
        request = Net::HTTP::Post.new(uri, 'Content-Type' => 'application/json')
        request.body = JSON.generate(model: opts.fetch(:model, 'nomic-embed-text'), input: text)
        response = http.request(request)
        raise "Ollama HTTP #{response.code}" unless response.is_a?(Net::HTTPSuccess)

        vector = JSON.parse(response.body).fetch('embeddings').first
        raise 'invalid embedding vector' unless vector.is_a?(Array) && !vector.empty? && vector.all? { |n| n.is_a?(Numeric) && n.finite? } && vector.any? { |n| !n.zero? }

        [vector, nil]
      rescue StandardError => e
        [nil, "embedding unavailable: #{e.class}: #{e.message}"]
      end

      # REXML's XPath and formatter recurse even though its parser accepts deep XML.
      private_class_method def self.validate_xml_nesting(opts = {})
        parser = REXML::Parsers::PullParser.new(opts[:data])
        depth = 0
        while parser.has_next?
          event = parser.pull
          depth += 1 if event.start_element?
          raise ArgumentError, 'artifact exceeds XML nesting limit (100)' if depth > 100

          depth -= 1 if event.end_element?
        end
      end

      private_class_method def self.ingestion_records(opts = {})
        source = opts[:source]
        if File.directory?(source)
          files = Dir.glob(File.join(source, '**', '*')).select { |file| File.file?(file) && !File.symlink?(file) && File.realpath(file).start_with?("#{source}/") }
          raise ArgumentError, 'source tree exceeds max_files' if files.length > opts.fetch(:max_files, 1000)

          return files.flat_map { |file| ingestion_records(opts.merge(source: file)) }
        end
        raise ArgumentError, 'artifact exceeds max_bytes' if File.size(source) > opts.fetch(:max_bytes, 32 * 1024 * 1024)

        data = File.binread(source)
        sha = Digest::SHA256.hexdigest(data)
        kind = opts[:format].to_s
        kind = File.extname(source).delete_prefix('.') if kind.empty?
        texts = case kind
                when 'xml', 'nmap', 'burp', 'zap'
                  raise ArgumentError, 'DTD/entities are not accepted' if data.match?(/<!DOCTYPE|<!ENTITY/i)

                  validate_xml_nesting(data: data)
                  doc = REXML::Document.new(data)
                  nodes = REXML::XPath.match(doc, '//host|//item|//alertitem|//site')
                  nodes = [doc.root] if nodes.empty?
                  nodes.each_with_index.map do |node, i|
                    node.each_recursive do |child|
                      next unless child.is_a?(REXML::Element) && child.attributes['base64'] == 'true'

                      child.text = Base64.strict_decode64(child.text.to_s).encode('UTF-8', invalid: :replace, undef: :replace)
                      child.attributes.delete('base64')
                    end
                    ["#{node.name}-#{i + 1}", node.to_s]
                  end
                when 'har', 'json'
                  parsed = JSON.parse(data)
                  entries = parsed.dig('log', 'entries') if parsed.is_a?(Hash)
                  (entries || [parsed]).each_with_index.map { |entry, i| ["record-#{i + 1}", JSON.generate(entry)] }
                when 'pcap', 'cap'
                  require 'packetfu'
                  PacketFu::PcapFile.read_packet_bytes(source).each_with_index.map do |bytes, i|
                    packet = PacketFu::Packet.parse(bytes)
                    ["packet-#{i + 1}", packet.inspect + " payload=#{packet.payload.to_s.inspect}"]
                  rescue StandardError => e
                    ["packet-#{i + 1}", "DEGRADED PacketFu decode unavailable (#{e.class}); raw frame bytes=#{bytes.bytesize} hex=#{bytes.unpack1('H*')} printable=#{bytes.scan(/[\x20-\x7e]{4,}/n).join(' ')}"]
                  end
                else
                  if data.include?("\x00") || %w[binary elf].include?(kind)
                    require 'pwn/plugins/radare2'
                    result = PWN::Plugins::Radare2.analyze_all(path: source)
                    [['binary-analysis', JSON.generate(result.slice(:backend, :status, :sha256, :functions, :strings, :imports, :symbols, :warnings))]]
                  else
                    data.force_encoding('UTF-8').lines.each_slice(40).with_index.map { |lines, i| ["lines-#{(i * 40) + 1}-#{(i * 40) + lines.length}", lines.join] }
                  end
                end
        texts.map { |locator, text| { source: source, sha256: sha, locator: locator, text: text } }
      end
    end
  end
end
