# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'

module PWN
  # PWN::Memory provides persistent cross-session memory for the pwn-ai agent.
  # Facts, user preferences,
  # environment details, lessons learned, and task state are stored in
  # ~/.pwn/memory.json and survive across REPL restarts / pwn-ai sessions.
  #
  # The pwn-ai agent (in agent mode) automatically receives relevant memory
  # injected into its system prompt. The agent can also call remember/recall
  # via ruby code blocks during execution loops.
  module Memory
    MEMORY_FILE = File.join(Dir.home, '.pwn', 'memory.json')

    # Supported Method Parameters::
    #   memory = PWN::Memory.load
    public_class_method def self.load
      FileUtils.mkdir_p(File.dirname(MEMORY_FILE))
      return {} unless File.exist?(MEMORY_FILE)

      raw = File.read(MEMORY_FILE)
      return {} if raw.strip.empty? || raw.strip == '{}'

      JSON.parse(raw, symbolize_names: true)
    rescue JSON::ParserError, EncodingError => e
      # Never silently return {} for a non-trivial file — that turns the next
      # consolidate/save into a full wipe. Quarantine + empty is safer only
      # when the caller opted in; default is keep last good and warn.
      warn "[pwn-ai/memory] load parse failed (#{e.class}: #{e.message}); refusing empty fallback for #{File.size(MEMORY_FILE)}B file"
      raise
    rescue StandardError => e
      warn "[pwn-ai/memory] load failed: #{e.class}: #{e.message}"
      raise
    end

    # Supported Method Parameters::
    #   PWN::Memory.save(mem: memory_hash)
    public_class_method def self.save(opts = {})
      mem = opts[:mem] ||= {}
      force = opts[:force] ? true : false
      FileUtils.mkdir_p(File.dirname(MEMORY_FILE))
      # 4.4 — flock + atomic rename (nightly practice × interactive)
      path = MEMORY_FILE
      # Guard: never clobber a non-empty memory.json with {} unless force.
      # Root cause of 2026-08-05 wipe: load-rescue→{} then consolidate/save.
      if !force && mem.respond_to?(:empty?) && mem.empty? && File.exist?(path) && File.size(path) > 4
        warn "[pwn-ai/memory] refusing empty overwrite of #{File.size(path)}B #{path} (pass force:true to clear)"
        return load_raw_or_empty(path: path)
      end
      tmp  = File.join(File.dirname(path), ".#{File.basename(path)}.#{Process.pid}.tmp")
      body = JSON.pretty_generate(mem)
      File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |f|
        f.flock(File::LOCK_EX)
        f.write(body)
        f.flush
        f.fsync
      end
      File.rename(tmp, path)
      mem
    ensure
      FileUtils.rm_f(tmp) if defined?(tmp) && tmp && File.exist?(tmp)
    end

    # Best-effort re-read used by the empty-overwrite guard (no raise).
    private_class_method def self.load_raw_or_empty(opts = {})
      path = opts[:path] || MEMORY_FILE
      return {} unless File.exist?(path)

      JSON.parse(File.read(path), symbolize_names: true)
    rescue StandardError
      {}
    end

    # Supported Method Parameters::
    #   PWN::Memory.remember(
    #     key: 'required - Symbol or String key for the memory fact',
    #     value: 'required - The value (any JSON serializable)',
    #     category: 'optional - e.g. :fact, :preference, :lesson, :env (default: :fact)',
    #     source: 'optional - :human | :reflect | :heuristic | :resolve | :consolidate (M3 provenance)',
    #     confidence: 'optional - 0.0..1.0 how sure the writer was (M3)',
    #     importance: 'optional - 0.0..1.0 retrieval/eviction weight (M2/M3)',
    #     ttl: 'optional - seconds until stale (M3; consolidate evicts stale low-conf first)'
    #   )
    public_class_method def self.remember(opts = {})
      key = opts[:key]
      value = opts[:value]
      category = opts[:category] || :fact

      raise 'ERROR: key and value are required' if key.nil? || value.nil?

      mem = load
      entry = {
        value: value,
        category: category.to_sym,
        timestamp: Time.now.utc.iso8601,
        # M3 — provenance & scoring so Learning.consolidate evicts by
        # (age/ttl)/(importance×confidence) instead of oldest-first, and
        # MemoryIndex.recall_semantic ranks by sim × recency × importance.
        source: (opts[:source] || 'pwn-ai').to_s,
        confidence: opts[:confidence]&.to_f&.clamp(0.0, 1.0),
        importance: opts[:importance]&.to_f&.clamp(0.0, 1.0),
        ttl: opts[:ttl]&.to_i
      }.compact
      mem[key.to_sym] = entry
      save(mem: mem)
      mem[key.to_sym]
    end

    # Supported Method Parameters::
    #   results = PWN::Memory.recall(
    #     query: 'optional - string to search keys/values/categories (simple match)',
    #     category: 'optional - filter by category',
    #     limit: 'optional - max results (default 50)'
    #   )
    public_class_method def self.recall(opts = {})
      query = opts[:query].to_s.downcase
      category = opts[:category]
      limit = opts[:limit] || 50

      mem = load
      results = mem.select do |k, v|
        match = true
        match &&= k.to_s.downcase.include?(query) || v[:value].to_s.downcase.include?(query) || v[:category].to_s.downcase.include?(query) if query && !query.empty?
        match &&= (v[:category] == category.to_sym) if category
        match
      end

      results.to_a.first(limit).to_h
    end

    # Supported Method Parameters::
    #   hits = PWN::Memory.recall_semantic(query: 'nmap sweep', limit: 6)
    #
    # Relevance-ranked recall via PWN::MemoryIndex (local Ollama embeddings
    # + cosine over ~/.pwn/memory.idx). Falls back to substring .recall
    # when no embedding backend is configured.
    public_class_method def self.recall_semantic(opts = {})
      return recall(query: opts[:query], limit: opts[:limit]) unless defined?(PWN::MemoryIndex) && PWN::MemoryIndex.available?

      PWN::MemoryIndex.recall_semantic(query: opts[:query], limit: opts[:limit])
    rescue StandardError
      recall(query: opts[:query], limit: opts[:limit])
    end

    # Supported Method Parameters::
    #   PWN::Memory.forget(key: :some_key)
    public_class_method def self.forget(opts = {}) # rubocop:disable Naming/PredicateMethod
      key = opts[:key]
      mem = load
      mem.delete(key.to_sym)
      # Last-key delete legitimately yields {}; force so empty-guard does not revive it.
      save(mem: mem, force: mem.empty?)
      true
    end

    # Supported Method Parameters::
    #   PWN::Memory.clear
    public_class_method def self.clear
      FileUtils.rm_f(MEMORY_FILE)
      save(mem: {}, force: true) # recreate empty file atomically
      {}
    end

    # Supported Method Parameters::
    #   context = PWN::Memory.to_context(limit: 20)
    #   (used internally by pwn-ai hook to inject into system prompt)
    public_class_method def self.to_context(opts = {})
      limit = opts[:limit] || 20
      mem = recall(limit: limit)
      return '' if mem.empty?

      ctx = "\n\nPERSISTENT MEMORY (cross-session facts, prefs, lessons - use PWN::Memory.remember to store new ones):\n"
      mem.each do |k, v|
        ctx += "- #{k} [#{v[:category]} @ #{v[:timestamp]}]: #{v[:value].to_s[0, 300]}\n"
      end
      ctx
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display Usage for this Module
    public_class_method def self.help
      puts <<~USAGE
        USAGE:
          mem = PWN::Memory.load
          PWN::Memory.remember(key: :user_prefers_ruby, value: 'Always prefer pure Ruby + RestClient patterns', category: :preference)
          facts = PWN::Memory.recall(query: 'recon', category: :fact, limit: 10)
          hits  = PWN::Memory.recall_semantic(query: 'recon', limit: 6)  # embedding-ranked
          PWN::Memory.forget(key: :some_key)
          PWN::Memory.clear
          context_str = PWN::Memory.to_context

          #{self}.authors
      USAGE
    end
  end
end
