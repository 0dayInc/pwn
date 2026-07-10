# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'digest'

module PWN
  # PWN::MemoryIndex is a lightweight local embedding index over
  # PWN::Memory (~/.pwn/memory.json) so PromptBuilder can inject the N
  # MOST-RELEVANT memories for the current request instead of the N
  # newest. Embeddings come from the local Ollama instance
  # (PWN::Env[:ai][:ollama][:embed_model], default 'nomic-embed-text') via
  # its native /api/embed endpoint — everything stays on-box.
  #
  # Index layout (~/.pwn/memory.idx):
  #   { "<key>": { "sha": "<sha16 of value>", "vec": [Float,…] }, … }
  #
  # Rebuilds are incremental: only entries whose value-sha changed are
  # (re)embedded, so a warm index costs one embed call (the query).
  module MemoryIndex
    INDEX_FILE = File.join(Dir.home, '.pwn', 'memory.idx')
    DEFAULT_EMBED_MODEL = 'nomic-embed-text'

    # Supported Method Parameters::
    #   bool = PWN::MemoryIndex.available?
    #
    # True when a local Ollama base_uri is configured. All public methods
    # degrade to substring recall when this is false.

    public_class_method def self.available?
      !ollama_base.nil?
    rescue StandardError
      false
    end

    # Supported Method Parameters::
    #   hits = PWN::MemoryIndex.recall_semantic(
    #     query: 'required - user request / search text',
    #     limit: 'optional - top-K by cosine similarity (default 6)'
    #   )
    #
    # Returns [{ key:, value:, category:, timestamp:, score: }, …]
    # (newest-first Memory.recall shape + :score) or falls back to
    # PWN::Memory.recall(query:) when embedding is unavailable.

    public_class_method def self.recall_semantic(opts = {})
      query = opts[:query].to_s
      limit = (opts[:limit] || 6).to_i
      mem   = PWN::Memory.load
      return [] if mem.empty? || query.strip.empty?

      qv = embed(texts: [query]).first
      return fallback(query: query, limit: limit) unless qv

      idx = refresh(mem: mem)
      scored = mem.map do |k, v|
        vec = idx.dig(k, :vec)
        next unless vec

        { key: k, value: v[:value], category: v[:category], timestamp: v[:timestamp], score: cosine(a: qv, b: vec) }
      end
      scored.compact.sort_by { |h| -h[:score] }.first(limit)
    rescue StandardError
      fallback(query: query, limit: limit)
    end

    # Supported Method Parameters::
    #   ctx = PWN::MemoryIndex.to_context(query:, limit: 6)
    #
    # Drop-in replacement for PWN::Memory.to_context that ranks by
    # relevance to +query+ instead of insertion order. Emitted format is
    # identical so PromptBuilder needs no special-casing.

    public_class_method def self.to_context(opts = {})
      hits = recall_semantic(query: opts[:query], limit: opts[:limit] || 6)
      return PWN::Memory.to_context(limit: opts[:limit] || 6) if hits.empty?

      ctx = "\n\nPERSISTENT MEMORY (relevance-ranked for this request - use PWN::Memory.remember to store new ones):\n"
      hits.each do |h|
        ctx += "- #{h[:key]} [#{h[:category]} @ #{h[:timestamp]}]: #{h[:value].to_s[0, 300]}\n"
      end
      ctx
    end

    # Supported Method Parameters::
    #   idx = PWN::MemoryIndex.refresh(mem: 'optional - preloaded PWN::Memory hash')
    #
    # Incrementally (re)embed changed entries and prune deleted keys.
    # Returns the in-memory index Hash keyed by memory key (Symbol).

    public_class_method def self.refresh(opts = {})
      mem = opts[:mem] || PWN::Memory.load
      idx = load_index
      idx.delete_if { |k, _| !mem.key?(k) }

      todo = mem.reject { |k, v| idx.dig(k, :sha) == sha(text: v[:value].to_s) }
      unless todo.empty?
        vecs = embed(texts: todo.values.map { |v| "#{v[:category]}: #{v[:value]}" })
        todo.keys.each_with_index do |k, i|
          next unless vecs[i]

          idx[k] = { sha: sha(text: mem[k][:value].to_s), vec: vecs[i] }
        end
        save_index(idx: idx)
      end
      idx
    rescue StandardError
      idx || {}
    end

    # Supported Method Parameters::
    #   vecs = PWN::MemoryIndex.embed(texts: ['a', 'b'])
    #
    # POST /api/embed on the local Ollama; returns Array<Array<Float>> (one
    # vector per input, nil on per-item failure). Batches of 32.

    public_class_method def self.embed(opts = {})
      texts = Array(opts[:texts]).map(&:to_s)
      base  = ollama_base
      return Array.new(texts.length) unless base && !texts.empty?

      model = (PWN::Env.dig(:ai, :ollama, :embed_model) if defined?(PWN::Env)) || DEFAULT_EMBED_MODEL
      browser = PWN::Plugins::TransparentBrowser.open(browser_type: :rest)
      rest    = browser[:browser]::Request
      headers = { content_type: 'application/json; charset=UTF-8' }
      token   = PWN::Env.dig(:ai, :ollama, :key) if defined?(PWN::Env)
      headers[:authorization] = "Bearer #{token}" if token

      out = []
      texts.each_slice(32) do |batch|
        resp = rest.execute(
          method: :post,
          url: "#{base}/ollama/api/embed",
          headers: headers,
          payload: { model: model, input: batch }.to_json,
          verify_ssl: false,
          timeout: 120
        )
        j = JSON.parse(resp, symbolize_names: true)
        out.concat(Array(j[:embeddings]))
      end
      out
    rescue StandardError
      Array.new(texts.length)
    end

    # Supported Method Parameters::
    #   PWN::MemoryIndex.reset

    public_class_method def self.reset
      FileUtils.rm_f(INDEX_FILE)
      {}
    end

    # -----------------------------------------------------------------
    # privates
    # -----------------------------------------------------------------

    private_class_method def self.load_index
      return {} unless File.exist?(INDEX_FILE)

      JSON.parse(File.read(INDEX_FILE), symbolize_names: true)
    rescue StandardError
      {}
    end

    private_class_method def self.save_index(opts = {})
      FileUtils.mkdir_p(File.dirname(INDEX_FILE))
      File.write(INDEX_FILE, JSON.generate(opts[:idx] || {}))
    end

    private_class_method def self.cosine(opts = {})
      a = opts[:a]
      b = opts[:b]
      return 0.0 unless a && b && a.length == b.length

      dot = na = nb = 0.0
      a.each_with_index do |x, i|
        y = b[i]
        dot += x * y
        na  += x * x
        nb  += y * y
      end
      return 0.0 if na.zero? || nb.zero?

      dot / (Math.sqrt(na) * Math.sqrt(nb))
    end

    private_class_method def self.sha(opts = {})
      Digest::SHA256.hexdigest(opts[:text].to_s)[0, 16]
    end

    private_class_method def self.ollama_base
      return nil unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

      b = PWN::Env.dig(:ai, :ollama, :base_uri).to_s
      b.start_with?('http') ? b.chomp('/') : nil
    end

    private_class_method def self.fallback(opts = {})
      PWN::Memory.recall(query: opts[:query], limit: opts[:limit]).map do |k, v|
        { key: k, value: v[:value], category: v[:category], timestamp: v[:timestamp], score: 0.0 }
      end
    rescue StandardError
      []
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display Usage for this Module

    public_class_method def self.help
      puts <<~USAGE
        USAGE:
          PWN::MemoryIndex.available?
          PWN::MemoryIndex.recall_semantic(query: 'nmap sweep', limit: 6)
          PWN::MemoryIndex.to_context(query: 'nmap sweep', limit: 6)  # PromptBuilder drop-in
          PWN::MemoryIndex.refresh                                    # incremental (re)embed
          PWN::MemoryIndex.embed(texts: ['a', 'b'])                   # raw vectors
          PWN::MemoryIndex.reset

          Config:
            PWN::Env[:ai][:ollama][:embed_model] = 'nomic-embed-text'  # or bge-m3, mxbai-embed-large

          #{self}.authors
      USAGE
    end
  end
end
