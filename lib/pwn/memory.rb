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
    # Lean retention — keep RL-quality signal, drop ephemeral bulk.
    VALUE_MAX_CHARS = 2_000
    PROTECT_KEY_PREFIXES = %w[operator_pref_ process_sop_ mistake_fix_ memory_].freeze
    PROTECT_CATEGORIES = %i[preference].freeze
    EPHEMERAL_KEY_PREFIXES = %w[session_].freeze
    EPHEMERAL_TTL_SECS = 7 * 86_400

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
      tmp = File.join(File.dirname(path), ".#{File.basename(path)}.#{Process.pid}.tmp")
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
      val = value.is_a?(String) ? value.to_s : value
      val = "#{val.to_s[0, VALUE_MAX_CHARS]}…[compacted]" if val.is_a?(String) && val.bytesize > VALUE_MAX_CHARS
      entry = {
        value: val,
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
    #   PWN::Memory.forget(
    #     key: :some_key,
    #     force: 'optional - Boolean bypass protect policy (default false)'
    #   )
    # Refuses PROTECT_KEY_PREFIXES / PROTECT_CATEGORIES unless force:true.
    public_class_method def self.forget(opts = {}) # rubocop:disable Naming/PredicateMethod
      key = opts[:key]
      raise 'ERROR: key is required' if key.nil?

      force = opts[:force] ? true : false
      mem = load
      entry = mem[key.to_sym]
      raise "ERROR: refusing to forget protected memory key #{key.inspect} (matches PROTECT_KEY_PREFIXES/PROTECT_CATEGORIES; pass force:true)" if entry && protected_entry?(key: key, entry: entry) && !force

      mem.delete(key.to_sym)
      # Last-key delete legitimately yields {}; force so empty-guard does not revive it.
      save(mem: mem, force: mem.empty?)
      true
    end

    # Supported Method Parameters::
    #   PWN::Memory.clear(force: true)
    # Requires force:true — protected prefs/SOPs must not vanish via bare clear.
    public_class_method def self.clear(opts = {})
      force = if opts.is_a?(Hash)
                opts[:force] ? true : false
              else
                false
              end
      raise 'ERROR: refusing Memory.clear without force:true (would drop PROTECT_KEY_PREFIXES/PROTECT_CATEGORIES)' unless force

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

    # True when a memory key must survive cap eviction / age GC.
    public_class_method def self.protected_entry?(opts = {})
      key = opts[:key].to_s
      entry = opts[:entry] || {}
      return true if PROTECT_KEY_PREFIXES.any? { |p| key.start_with?(p) }
      return true if PROTECT_CATEGORIES.map(&:to_s).include?(entry[:category].to_s)

      false
    end

    # Supported Method Parameters::
    #   result = PWN::Memory.lean!(
    #     dry_run: 'optional - Boolean plan only (default false)',
    #     value_max_chars: 'optional - truncate values (default VALUE_MAX_CHARS)',
    #     ephemeral_ttl_secs: 'optional - drop expired session_* keys'
    #   )
    #
    # Compact overlong values and drop expired ephemeral session_* keys.
    # Never removes protected prefs/SOPs/fix lessons. Safe with empty-save guard.
    public_class_method def self.lean!(opts = {})
      dry = opts[:dry_run] ? true : false
      vmax = (opts[:value_max_chars] || VALUE_MAX_CHARS).to_i
      ttl_secs = (opts[:ephemeral_ttl_secs] || EPHEMERAL_TTL_SECS).to_i
      mem = load
      before_bytes = File.exist?(MEMORY_FILE) ? File.size(MEMORY_FILE) : 0
      removed = []
      truncated = []
      now = Time.now.utc

      mem.each do |k, v|
        key = k.to_s
        next if protected_entry?(key: key, entry: v)

        if EPHEMERAL_KEY_PREFIXES.any? { |p| key.start_with?(p) }
          age = begin
            now - Time.parse(v[:timestamp].to_s)
          rescue StandardError
            ttl_secs + 1
          end
          exp = v[:ttl].to_i.positive? ? v[:ttl].to_i : ttl_secs
          if age > exp
            removed << key
            next
          end
        end

        next unless v[:value].is_a?(String) && v[:value].to_s.bytesize > vmax

        truncated << key
        v[:value] = "#{v[:value].to_s[0, vmax]}…[compacted]" unless dry
      end

      removed.each { |k| mem.delete(k.to_sym) } unless dry
      save(mem: mem, force: mem.empty?) unless dry || (removed.empty? && truncated.empty?)

      {
        removed: removed.length,
        truncated: truncated.length,
        remaining: mem.size,
        removed_keys: removed.first(20),
        truncated_keys: truncated.first(20),
        bytes_before: before_bytes,
        bytes_after: if dry
                       before_bytes
                     else
                       (File.exist?(MEMORY_FILE) ? File.size(MEMORY_FILE) : 0)
                     end,
        dry_run: dry
      }
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
          PWN::Memory.forget(key: :operator_pref_x) rescue puts('protected')
          PWN::Memory.clear(force: true)
          context_str = PWN::Memory.to_context
          PWN::Memory.lean!(dry_run: true)  # drop expired session_* + truncate values

          #{self}.authors
      USAGE
    end
  end
end
