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
    #     category: 'optional - filter by category (:session = transcript only)',
    #     limit: 'optional - max results (default 50)',
    #     session_id: 'optional - current session (default Env/Pry active id)'
    #   )
    # Returns session turns first (previous assistant response -> older, current
    # session only, empty/invalid skipped), then durable memory newest-first.

    public_class_method def self.recall(opts = {})
      query = opts[:query].to_s.downcase
      category = opts[:category]
      limit = (opts[:limit] || 50).to_i
      limit = 50 if limit <= 0
      session_id = opts[:session_id]
      session_id = current_session_id if session_id.to_s.empty?
      # Default ON for memory_recall tool UX. to_context passes false so the
      # injected MEMORY block stays durable cross-session facts only.
      include_session = if opts.key?(:include_session)
                          opts[:include_session] ? true : false
                        else
                          true
                        end

      ordered = {}

      # 1) Current-session turns first: start at previous response, walk older.
      #    Skips empty/invalid turns. Stays scoped to this session only.
      if include_session && !(category && category.to_sym != :session)
        session_turns(session_id: session_id, query: query, limit: limit).each do |entry|
          break if ordered.length >= limit

          key = entry[:key]
          ordered[key] = entry.except(:key)
        end
      end

      # 2) Durable ~/.pwn/memory.json (newest timestamp first) fills remaining slots.
      if ordered.length < limit && !(category && category.to_sym == :session)
        mem = load
        durable = mem.select do |k, v|
          match = true
          if query && !query.empty?
            match &&= k.to_s.downcase.include?(query) ||
                      v[:value].to_s.downcase.include?(query) ||
                      v[:category].to_s.downcase.include?(query)
          end
          match &&= (v[:category].to_s == category.to_s) if category
          match
        end
        durable_sorted = durable.sort_by do |k, v|
          [-Time.parse(v[:timestamp].to_s).to_i, k.to_s]
        rescue StandardError
          [0, k.to_s]
        end
        durable_sorted.each do |k, v|
          break if ordered.length >= limit
          next if ordered.key?(k)

          ordered[k] = v
        end
      end

      ordered
    end

    # Resolve the active pwn-ai session id (Env, then Pry config).
    public_class_method def self.current_session_id(opts = {})
      sid = opts[:session_id].to_s
      return sid unless sid.empty?

      if defined?(PWN::Env) && PWN::Env.is_a?(Hash)
        sid = PWN::Env.dig(:ai, :session_id).to_s
        return sid unless sid.empty?
      end

      return Pry.config.pwn_ai_session_id.to_s if defined?(Pry) && Pry.respond_to?(:config) && Pry.config.respond_to?(:pwn_ai_session_id)

      ''
    end

    # Walk the current session transcript from the previous assistant response
    # backward (previous -> older). Empty/invalid turns are skipped.
    # Returns Array of hashes with :key plus entry fields (role/value/...).
    public_class_method def self.session_turns(opts = {})
      sid = opts[:session_id].to_s
      sid = current_session_id if sid.empty?
      return [] if sid.empty?
      return [] unless defined?(PWN::Sessions)

      query = opts[:query].to_s.downcase
      limit = (opts[:limit] || 50).to_i
      limit = 50 if limit <= 0

      rows = PWN::Sessions.load(session_id: sid)
      return [] if rows.nil? || rows.empty?

      valid = []
      rows.each_with_index do |e, idx|
        next unless e.is_a?(Hash)

        role = e[:role].to_s
        content = e[:content].to_s
        next if content.strip.empty?
        next unless %w[assistant user tool system observation].include?(role)
        # Skip the bootstrap system line when it has no useful body.
        next if role == 'system' && content.match?(/\ASession started:/i)

        valid << {
          idx: idx,
          role: role,
          content: content,
          timestamp: e[:timestamp]
        }
      end
      return [] if valid.empty?

      # Previous response = most recent non-empty assistant turn in-session.
      last_asst = valid.rindex { |e| e[:role] == 'assistant' }
      # If no assistant yet, still walk backward from the latest valid turn.
      start_at = last_asst || (valid.length - 1)
      backward = valid[0..start_at].reverse

      hits = []
      backward.each do |e|
        break if hits.length >= limit

        content = e[:content]
        role = e[:role]
        if query && !query.empty? && !(content.downcase.include?(query) ||
                      role.include?(query) ||
                      "session_#{sid}".include?(query))
          next
        end

        hits << {
          key: :"session_turn_#{sid}_#{e[:idx]}",
          value: content,
          category: :session,
          role: role,
          timestamp: e[:timestamp],
          session_id: sid,
          source: 'session_backward'
        }
      end
      hits
    end

    # Supported Method Parameters::
    #   dialog = PWN::Memory.recent_dialog(
    #     session_id: 'optional',
    #     pairs: 'optional - max user/assistant pairs (default 2)',
    #     max_chars: 'optional - per-turn truncation (default 1200)'
    #   )
    # Chronological user/assistant turns ending at the previous assistant
    # response (current session only). Empty/invalid/tool noise skipped.

    public_class_method def self.recent_dialog(opts = {})
      pairs = (opts[:pairs] || 2).to_i
      pairs = 2 if pairs <= 0
      max_chars = (opts[:max_chars] || 1_200).to_i
      max_chars = 1_200 if max_chars <= 0
      turns = session_turns(session_id: opts[:session_id], limit: pairs * 6)
      dialog = turns.select { |t| %w[user assistant].include?(t[:role].to_s) }
      # session_turns is previous-assistant-first (newest → older). Take the
      # newest 2*pairs dialog turns and flip to chronological for prompts.
      slice = dialog.first(pairs * 2).reverse
      slice.map do |t|
        body = t[:value].to_s
        body = "#{body[0, max_chars]}…[truncated]" if body.length > max_chars
        {
          role: t[:role].to_s,
          content: body,
          timestamp: t[:timestamp],
          session_id: t[:session_id]
        }
      end
    rescue StandardError
      []
    end

    # Meta prior-turn recall asks (not substantive conversational content).
    # Used so nested "what did you say when I said that?" skips the intermediate
    # recall Q/A and lands on the real user↔assistant pair.
    META_RECALL_USER_RX = /
      \A\s*(?:and\s+)?(?:
        what\s+did\s+i\s+|
        what\s+was\s+my\s+last|
        how\s+did\s+you\s+respond|
        how\s+did\s+you\s+(?:just\s+)?(?:answer|reply)|
        what\s+(?:was|is)\s+your\s+(?:last|previous|prior)\s+|
        what\s+did\s+you\s+(?:just\s+)?(?:say|answer|reply|respond)|
        remind\s+me\s+what\s+|
        repeat\s+(?:my\s+|your\s+)?(?:last|previous)|
        last\s+thing\s+i\s+said|
        say\s+that\s+again
      )
    /ix

    META_RECALL_ASST_RX = /
      \A\s*(?:
        You\s+just\s+said:|
        Immediately\s+prior\s+(?:user\s+message|assistant\s+response):|
        I\s+do\s+not\s+have\s+a\s+prior\s+assistant\s+reply
      )
    /ix

    # Previous non-empty user message in the active session (what the human
    # "just said" before the current request). Nil when none.
    # skip_meta:true walks past pure-recall intermediate asks.
    public_class_method def self.prior_user_message(opts = {})
      pairs = (opts[:pairs] || 6).to_i
      max_chars = opts[:max_chars] || 4_000
      skip_meta = opts.key?(:skip_meta) ? opts[:skip_meta] : false
      dialog = recent_dialog(session_id: opts[:session_id], pairs: pairs, max_chars: max_chars)
      dialog.reverse.find do |t|
        next false unless t[:role].to_s == 'user'
        next false if skip_meta && meta_recall_user?(t[:content])

        true
      end
    rescue StandardError
      nil
    end

    # Previous non-empty assistant message in the active session.
    # skip_meta:true walks past canned recall answers so the substantive reply
    # stays findable after nested "what did you say when…" follow-ups.
    public_class_method def self.prior_assistant_message(opts = {})
      pairs = (opts[:pairs] || 6).to_i
      max_chars = opts[:max_chars] || 4_000
      skip_meta = opts.key?(:skip_meta) ? opts[:skip_meta] : false
      dialog = recent_dialog(session_id: opts[:session_id], pairs: pairs, max_chars: max_chars)
      dialog.reverse.find do |t|
        next false unless t[:role].to_s == 'assistant'
        next false if skip_meta && meta_recall_assistant?(t[:content])

        true
      end
    rescue StandardError
      nil
    end

    # Build chronological user→assistant pairs from the active session.
    # Each pair is { user:, assistant:, user_content:, assistant_content: }.
    # Solo user turns (no reply yet) are omitted unless include_orphan_user:true.
    public_class_method def self.turn_pairs(opts = {})
      pairs_n = (opts[:pairs] || 8).to_i
      pairs_n = 8 if pairs_n <= 0
      max_chars = (opts[:max_chars] || 4_000).to_i
      dialog = recent_dialog(session_id: opts[:session_id], pairs: pairs_n, max_chars: max_chars)
      out = []
      i = 0
      while i < dialog.length
        t = dialog[i]
        if t[:role].to_s == 'user'
          nxt = dialog[i + 1]
          if nxt && nxt[:role].to_s == 'assistant'
            out << {
              user: t,
              assistant: nxt,
              user_content: t[:content].to_s,
              assistant_content: nxt[:content].to_s
            }
            i += 2
            next
          elsif opts[:include_orphan_user]
            out << {
              user: t,
              assistant: nil,
              user_content: t[:content].to_s,
              assistant_content: nil
            }
          end
        end
        i += 1
      end
      out
    rescue StandardError
      []
    end

    # Find a user↔assistant pair in the active session.
    #   match: optional substring / quoted utterance to locate the user turn
    #   skip_meta: skip pure-recall intermediate pairs (default true)
    # Returns the newest matching pair hash, or nil.
    public_class_method def self.find_turn_pair(opts = {})
      match = opts[:match].to_s.strip
      skip_meta = opts.key?(:skip_meta) ? opts[:skip_meta] : true
      pairs = turn_pairs(
        session_id: opts[:session_id],
        pairs: opts[:pairs] || 12,
        max_chars: opts[:max_chars] || 4_000
      )
      return nil if pairs.empty?

      candidates = pairs
      if skip_meta
        candidates = pairs.reject do |p|
          meta_recall_user?(p[:user_content]) || meta_recall_assistant?(p[:assistant_content])
        end
        candidates = pairs if candidates.empty?
      end

      return candidates.last if match.empty?

      needle = normalize_utterance(match)
      return nil if needle.empty?

      # Prefer exact normalized equality, then include, newest first.
      exact = candidates.reverse.find { |p| normalize_utterance(p[:user_content]) == needle }
      return exact if exact

      candidates.reverse.find do |p|
        body = normalize_utterance(p[:user_content])
        body.include?(needle) || needle.include?(body)
      end
    rescue StandardError
      nil
    end

    public_class_method def self.meta_recall_user?(opts = {})
      text = opts.is_a?(Hash) ? opts[:text] : opts
      text.to_s.match?(META_RECALL_USER_RX)
    end

    public_class_method def self.meta_recall_assistant?(opts = {})
      text = opts.is_a?(Hash) ? opts[:text] : opts
      text.to_s.match?(META_RECALL_ASST_RX)
    end

    public_class_method def self.normalize_utterance(opts = {})
      text = opts.is_a?(Hash) ? opts[:text] : opts
      text.to_s.downcase.gsub(/[`"'“”‘’]/, '').gsub(/\s+/, ' ').strip
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
      mem = recall(limit: limit, include_session: false)
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
      puts "USAGE:
        # Run load and return its result
        #{self}.load

        # Run save and return its result
        #{self}.save(
          mem: 'optional - mem value consumed by #save',
          force: 'optional - force value consumed by #save'
        )

        # Run remember and return its result
        #{self}.remember(
          key: 'required - Symbol or String key for the memory fact',
          value: 'required - The value (any JSON serializable)',
          category: 'optional - e.g. :fact, :preference, :lesson, :env (default: :fact)',
          source: 'optional - :human | :reflect | :heuristic | :resolve | :consolidate (M3 provenance)',
          confidence: 'optional - 0.0..1.0 how sure the writer was (M3)',
          importance: 'optional - 0.0..1.0 retrieval/eviction weight (M2/M3)',
          ttl: 'optional - seconds until stale (M3; consolidate evicts stale low-conf first)'
        )

        # Run recall and return its result
        #{self}.recall(
          query: 'optional - string to search keys/values/categories (simple match)',
          category: 'optional - filter by category (:session = transcript only)',
          limit: 'optional - max results (default 50)',
          session_id: 'optional - current session (default Env/Pry active id)',
          include_session: 'optional - include session value consumed by #recall'
        )

        # Resolve the active pwn-ai session id (Env, then Pry config)
        #{self}.current_session_id(
          session_id: 'optional - session id value consumed by #current_session_id'
        )

        # Walk the current session transcript from the previous assistant response
        #{self}.session_turns(
          session_id: 'optional - session id value consumed by #session_turns',
          query: 'required - search query string',
          limit: 'optional - limit value consumed by #session_turns'
        )

        # Run recent dialog and return its result
        #{self}.recent_dialog(
          session_id: 'optional - session id value consumed by #recent_dialog',
          pairs: 'optional - max user/assistant pairs (default 2)',
          max_chars: 'optional - per-turn truncation (default 1200)'
        )

        # Previous non-empty user message in the active session (what the human
        #{self}.prior_user_message(
          pairs: 'optional - pairs value consumed by #prior_user_message',
          max_chars: 'optional - max chars value consumed by #prior_user_message (defaults to 4_000)',
          skip_meta: 'optional - skip meta value consumed by #prior_user_message',
          session_id: 'optional - session id value consumed by #prior_user_message'
        )

        # Previous non-empty assistant message in the active session
        #{self}.prior_assistant_message(
          pairs: 'optional - pairs value consumed by #prior_assistant_message',
          max_chars: 'optional - max chars value consumed by #prior_assistant_message (defaults to 4_000)',
          skip_meta: 'optional - skip meta value consumed by #prior_assistant_message',
          session_id: 'optional - session id value consumed by #prior_assistant_message'
        )

        # Build chronological user→assistant pairs from the active session
        #{self}.turn_pairs(
          pairs: 'optional - pairs value consumed by #turn_pairs',
          max_chars: 'optional - max chars value consumed by #turn_pairs',
          session_id: 'optional - session id value consumed by #turn_pairs',
          include_orphan_user: 'optional - include orphan user value consumed by #turn_pairs'
        )

        # Find a user↔assistant pair in the active session
        #{self}.find_turn_pair(
          match: 'required - match value consumed by #find_turn_pair',
          skip_meta: 'optional - skip meta value consumed by #find_turn_pair',
          session_id: 'optional - session id value consumed by #find_turn_pair',
          pairs: 'optional - pairs value consumed by #find_turn_pair (defaults to 12)',
          max_chars: 'optional - max chars value consumed by #find_turn_pair (defaults to 4_000)'
        )

        # Run meta recall user and return its result
        #{self}.meta_recall_user?(
          text: 'optional - text value consumed by #meta_recall_user?'
        )

        # Run meta recall assistant and return its result
        #{self}.meta_recall_assistant?(
          text: 'optional - text value consumed by #meta_recall_assistant?'
        )

        # Run normalize utterance and return its result
        #{self}.normalize_utterance(
          text: 'optional - text value consumed by #normalize_utterance'
        )

        # Run recall semantic and return its result
        #{self}.recall_semantic(
          query: 'optional - search query string',
          limit: 'optional - limit value consumed by #recall_semantic'
        )

        # Refuses PROTECT_KEY_PREFIXES / PROTECT_CATEGORIES unless force:true
        #{self}.forget(
          key: 'required - key value consumed by #forget',
          force: 'optional - Boolean bypass protect policy (default false)'
        )

        # Requires force:true — protected prefs/SOPs must not vanish via bare clear
        #{self}.clear(
          force: 'required - force value consumed by #clear'
        )

        # Run to context and return its result
        #{self}.to_context(
          limit: 'optional - limit value consumed by #to_context (defaults to 20)'
        )

        # True when a memory key must survive cap eviction / age GC
        #{self}.protected_entry?(
          key: 'optional - key value consumed by #protected_entry?',
          entry: 'optional - entry value consumed by #protected_entry?'
        )

        # Run lean and return its result
        #{self}.lean!(
          dry_run: 'optional - Boolean plan only (default false)',
          value_max_chars: 'optional - truncate values (default VALUE_MAX_CHARS)',
          ephemeral_ttl_secs: 'optional - drop expired session_* keys'
        )

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
      constants.sort
    end
  end
end
