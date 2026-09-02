# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'securerandom'
require 'digest'
require 'zlib'

module PWN
  # PWN::Sessions provides session management for pwn-ai (and other drivers)
  # — list, resume, transcripts, and stats.
  # Sessions are stored as JSONL transcripts in ~/.pwn/sessions/ for durability
  # and easy search/append. pwn-ai agent mode auto-creates and appends to a
  # session on each activation.
  module Sessions
    SESSIONS_DIR = File.join(Dir.home, '.pwn', 'sessions')
    # Lean retention — pin gold/mistake refs; drop stubs and unreferenced age.
    RETAIN_DAYS = 30
    HOT_DAYS = 14
    MIN_STUB_BYTES = 200
    TOOL_CONTENT_MAX = 1_500
    ASSISTANT_CONTENT_MAX = 8_000
    COMPACT_SIZE_FLOOR = 100_000
    MAX_FILES = 400
    GOLD_MIN_SCORE = 0.6

    # Supported Method Parameters::
    #   dir = PWN::Sessions.sessions_dir
    public_class_method def self.sessions_dir
      FileUtils.mkdir_p(SESSIONS_DIR)
      SESSIONS_DIR
    end

    # Supported Method Parameters::
    #   sessions = PWN::Sessions.list
    public_class_method def self.list
      dir = sessions_dir
      Dir.glob(File.join(dir, '*.jsonl')).reverse.map do |f|
        {
          id: File.basename(f, '.jsonl'),
          path: f,
          size: File.size(f),
          mtime: File.mtime(f).utc.iso8601,
          lines: File.readlines(f).count
        }
      end
    end

    # Supported Method Parameters::
    #   session = PWN::Sessions.create(
    #     title: 'optional - human title',
    #     source: 'optional - e.g. pwn-ai',
    #     id: 'optional - fixed session id (tests / replay); default timestamp_hex'
    #   )
    public_class_method def self.create(opts = {})
      dir = sessions_dir
      id = opts[:id].to_s.strip
      if id.empty?
        ts = Time.now.utc.strftime('%Y%m%d_%H%M%S')
        rand = SecureRandom.hex(4)
        id = "#{ts}_#{rand}"
      end
      path = File.join(dir, "#{id}.jsonl")
      raise "Session #{id} already exists" if File.exist?(path)

      meta = {
        id: id,
        title: opts[:title] || "pwn-ai session #{id}",
        source: opts[:source] || 'pwn-ai',
        created_at: Time.now.utc.iso8601
      }

      File.open(path, 'w') do |f|
        f.puts(JSON.dump(role: 'system', content: "Session started: #{meta[:title]}", timestamp: meta[:created_at]))
      end
      { id: id, path: path, meta: meta }
    end

    # Supported Method Parameters::
    #   PWN::Sessions.append(
    #     session_id: 'required',
    #     role: 'user|assistant|system|observation',
    #     content: 'the message or obs'
    #   )
    public_class_method def self.append(opts = {})
      sid = opts[:session_id]
      raise 'ERROR: session_id required' unless sid

      path = File.join(sessions_dir, "#{sid}.jsonl")
      raise "Session #{sid} not found" unless File.exist?(path)

      role = (opts[:role] || 'user').to_s
      content = opts[:content]
      if content.is_a?(String)
        # Write-path policy: cap bulk by role using compact limits so append
        # cannot grow transcripts past TOOL_CONTENT_MAX / ASSISTANT_CONTENT_MAX.
        cap = case role
              when 'tool' then TOOL_CONTENT_MAX
              when 'assistant' then ASSISTANT_CONTENT_MAX
              else ASSISTANT_CONTENT_MAX * 2
              end
        content = "#{content[0, cap]}…[compacted]" if content.bytesize > cap
        content = redact(content: content)
      end
      entry = {
        role: role,
        content: content,
        timestamp: Time.now.utc.iso8601
      }
      File.open(path, 'a') { |f| f.puts(JSON.dump(entry)) }
      entry
    end

    # Supported Method Parameters::
    #   transcript = PWN::Sessions.load(session_id: 'required')
    public_class_method def self.load(opts = {})
      sid = opts[:session_id]
      path = File.join(sessions_dir, "#{sid}.jsonl")
      return [] unless File.exist?(path)

      File.readlines(path).map { |l| JSON.parse(l, symbolize_names: true) }
    end

    # Newest session that is not exclude_session_id (the prior pwn-ai run).
    #
    # Supported Method Parameters::
    #   id = PWN::Sessions.previous_id(
    #     exclude_session_id: 'optional - current session to skip'
    #   )
    public_class_method def self.previous_id(opts = {})
      exclude = opts[:exclude_session_id].to_s
      rows = list.sort_by { |s| [s[:mtime].to_s, s[:id].to_s] }.reverse
      hit = rows.find { |s| s[:id].to_s != exclude }
      hit && hit[:id].to_s
    rescue StandardError
      nil
    end

    # Search prior session transcripts for query terms. Current session is
    # excluded by default — that tail is already in RECENT TURNS.
    #
    # Supported Method Parameters::
    #   hits = PWN::Sessions.recall(
    #     query: 'optional - substring / tokens to match',
    #     exclude_session_id: 'optional - skip this id (current session)',
    #     include_current: 'optional - Boolean include excluded id (default false)',
    #     limit: 'optional - max hits (default 12)',
    #     max_files: 'optional - newest files to scan (default 40)',
    #     truncate: 'optional - chars per hit (default 280)'
    #   )
    public_class_method def self.recall(opts = {})
      query = opts[:query].to_s.downcase
      tokens = query.split(/\W+/).reject { |t| t.length < 3 }
      limit = (opts[:limit] || 12).to_i
      limit = 12 if limit <= 0
      max_files = (opts[:max_files] || 40).to_i
      max_files = 40 if max_files <= 0
      trunc = (opts[:truncate] || 280).to_i
      trunc = 280 if trunc <= 0
      exclude = opts[:exclude_session_id].to_s
      include_current = opts[:include_current] == true

      hits = []
      target = opts[:target].to_s.downcase
      list.sort_by { |s| s[:mtime].to_s }.reverse.first(max_files).each do |sess|
        sid = sess[:id].to_s
        next if !include_current && !exclude.empty? && sid == exclude

        load(session_id: sid).each do |row|
          next unless row.is_a?(Hash)
          next unless %w[user assistant].include?(row[:role].to_s)

          body = row[:content].to_s
          next if body.strip.empty?
          next if !target.empty? && !body.downcase.include?(target)

          score = recall_score(body: body.downcase, query: query, tokens: tokens)
          next if score <= 0 && target.empty?

          score = [score, 1].max unless target.empty?

          hits << {
            session_id: sid,
            role: row[:role].to_s,
            timestamp: row[:timestamp],
            content: body.length > trunc ? "#{body[0, trunc]}…[truncated]" : body,
            score: score
          }
        end
      end
      hits.sort_by { |h| [-h[:score].to_f, h[:timestamp].to_s] }.first(limit)
    rescue StandardError
      []
    end

    private_class_method def self.recall_score(opts = {})
      body = opts[:body].to_s
      query = opts[:query].to_s
      tokens = Array(opts[:tokens])
      return 1 if query.empty?

      score = 0
      score += 5 if !query.empty? && body.include?(query)
      expand_tokens(tokens: tokens).each { |tok| score += 1 if body.include?(tok) }
      score
    end

    private_class_method def self.expand_tokens(opts = {})
      tokens = Array(opts[:tokens]).map(&:to_s)
      table = {
        'bypass' => %w[evasion evade],
        'evasion' => %w[bypass evade],
        'throttle' => %w[rate limit ratelimit],
        'rate' => %w[throttle],
        'limit' => %w[throttle],
        'login' => %w[auth authentication]
      }
      tokens.flat_map { |tok| [tok] + Array(table[tok]) }.uniq
    end

    # Supported Method Parameters::
    #   history_for_ai = PWN::Sessions.to_response_history(session_id:)
    #   (converts transcript to the response_history format used by PWN::AI::* .chat)
    public_class_method def self.to_response_history(opts = {})
      transcript = load(session_id: opts[:session_id])
      choices = transcript.map do |e|
        {
          role: e[:role],
          content: e[:content]
        }
      end

      {
        id: opts[:session_id],
        object: 'session.transcript',
        model: 'pwn-ai',
        usage: {},
        choices: choices
      }
    end

    # Current-session conversation for the next LLM call. User + assistant
    # only (no tool/observation). Always on — not gated by recall wording.
    # Tail-window by max_chars so a long JSONL cannot blow the context.
    #
    #   msgs = PWN::Sessions.to_llm_messages(
    #     session_id: 'required',
    #     max_chars: 'optional - keep newest turns under this (default 48_000)',
    #     skip_request: 'optional - drop a trailing user line equal to this'
    #   )
    public_class_method def self.to_llm_messages(opts = {})
      sid = opts[:session_id]
      return [] if sid.to_s.empty?

      max_chars = opts[:max_chars].to_i
      max_chars = 48_000 if max_chars <= 0
      skip = opts[:skip_request].to_s
      rows = load(session_id: sid).select do |row|
        next false unless row.is_a?(Hash)

        role = row[:role].to_s
        next false unless %w[user assistant].include?(role)

        body = row[:content].to_s
        next false if body.strip.empty?

        true
      end
      if !skip.empty? && rows.last && rows.last[:role].to_s == 'user' && rows.last[:content].to_s == skip
        rows = rows[0...-1]
      elsif !skip.empty?
        rows = rows.reject { |row| row[:role].to_s == 'user' && row[:content].to_s == skip }
      end

      picked = []
      used = 0
      rows.reverse_each do |row|
        body = row[:content].to_s
        n = body.length
        break if picked.any? && (used + n) > max_chars

        picked.unshift(role: row[:role].to_s, content: body)
        used += n
      end
      picked
    rescue StandardError
      []
    end

    # Supported Method Parameters::
    #   PWN::Sessions.delete(
    #     session_id: 'required',
    #     force: 'optional - Boolean bypass pin policy (default false)'
    #   )
    # Refuses deletion of pinned sessions (hot/gold/mistake/current) unless force:true.
    public_class_method def self.delete(opts = {}) # rubocop:disable Naming/PredicateMethod
      sid = opts[:session_id]
      raise 'ERROR: session_id required' if sid.to_s.empty?

      force = opts[:force] ? true : false
      path = File.join(sessions_dir, "#{sid}.jsonl")
      unless force
        pins = protected_session_ids(current_session_id: opts[:current_session_id])
        raise "ERROR: refusing to delete protected session #{sid.inspect} (pinned by HOT_DAYS/gold/mistakes/current; pass force:true)" if pins.include?(sid.to_s)
      end

      FileUtils.rm_f(path)
      true
    end

    # Supported Method Parameters::
    #   stats = PWN::Sessions.stats
    public_class_method def self.stats
      sessions = list
      {
        total_sessions: sessions.size,
        total_lines: sessions.sum { |s| s[:lines] },
        oldest: sessions.last ? sessions.last[:mtime] : nil,
        newest: sessions.first ? sessions.first[:mtime] : nil
      }
    end

    # Supported Method Parameters::
    #   result = PWN::Sessions.lean!(
    #     dry_run: 'optional - Boolean (default false)',
    #     retain_days: 'optional - drop unreferenced older than this',
    #     hot_days: 'optional - always keep newer than this',
    #     max_files: 'optional - soft file cap after protections',
    #     current_session_id: 'optional - never delete this id'
    #   )
    #
    # Reference-protect sessions cited by gold learning outcomes and open
    # mistakes. Delete stubs and aged unreferenced files. Compact oversized
    # tool/assistant content on kept cold transcripts.
    public_class_method def self.lean!(opts = {})
      dry = opts[:dry_run] ? true : false
      retain_days = (opts[:retain_days] || RETAIN_DAYS).to_f
      hot_days = (opts[:hot_days] || HOT_DAYS).to_f
      max_files = (opts[:max_files] || MAX_FILES).to_i
      tool_max = (opts[:tool_content_max] || TOOL_CONTENT_MAX).to_i
      asst_max = (opts[:assistant_content_max] || ASSISTANT_CONTENT_MAX).to_i
      current = opts[:current_session_id].to_s
      current = PWN::Env.dig(:ai, :session_id).to_s if current.empty? && defined?(PWN::Env)

      dir = sessions_dir
      files = Dir.glob(File.join(dir, '*.jsonl'))
      before_bytes = files.sum { |f| File.size(f) }
      now = Time.now.utc

      protect = protected_session_ids(
        current_session_id: current,
        hot_days: hot_days,
        retain_days: retain_days,
        now: now
      )

      deleted = []
      compacted = []
      protected_n = 0

      # Classify
      entries = files.map do |path|
        id = File.basename(path, '.jsonl')
        mtime = File.mtime(path).utc
        age = (now - mtime) / 86_400.0
        size = File.size(path)
        pinned = protect.include?(id) || age <= hot_days
        protected_n += 1 if pinned
        { id: id, path: path, age: age, size: size, pinned: pinned, mtime: mtime }
      end

      # Delete stubs and aged unreferenced
      entries.each do |e|
        next if e[:pinned]

        stub = e[:size] < MIN_STUB_BYTES && stub_session?(path: e[:path])
        aged = e[:age] > retain_days
        next unless stub || aged

        deleted << e[:id]
        FileUtils.rm_f(e[:path]) unless dry
      end

      # Refresh remaining after deletes
      remaining = entries.reject { |e| deleted.include?(e[:id]) }

      # Enforce max_files on unpinned oldest-first
      if remaining.size > max_files
        unpinned = remaining.reject { |e| e[:pinned] }.sort_by { |e| e[:mtime] }
        over = remaining.size - max_files
        unpinned.first(over).each do |e|
          deleted << e[:id]
          FileUtils.rm_f(e[:path]) unless dry
          remaining.delete(e)
        end
      end

      # Compact large/cold kept files
      remaining.each do |e|
        next if e[:age] <= hot_days && e[:size] < COMPACT_SIZE_FLOOR
        next if e[:size] < COMPACT_SIZE_FLOOR && e[:age] <= retain_days

        changed = compact_transcript!(
          path: e[:path],
          tool_max: tool_max,
          asst_max: asst_max,
          dry_run: dry
        )
        compacted << e[:id] if changed
      end

      after_files = Dir.glob(File.join(dir, '*.jsonl'))
      after_bytes = after_files.sum { |f| File.size(f) }

      {
        deleted: deleted.length,
        deleted_ids: deleted.first(30),
        compacted: compacted.length,
        compacted_ids: compacted.first(30),
        protected: protected_n,
        remaining: after_files.size,
        bytes_before: before_bytes,
        bytes_after: dry ? before_bytes : after_bytes,
        dry_run: dry
      }
    end

    # Build the pin set from learning gold + open mistakes + hot files + current.
    public_class_method def self.protected_session_ids(opts = {})
      now = opts[:now] || Time.now.utc
      hot_days = (opts[:hot_days] || HOT_DAYS).to_f
      retain_days = (opts[:retain_days] || RETAIN_DAYS).to_f
      pins = {}
      pins[opts[:current_session_id].to_s] = true unless opts[:current_session_id].to_s.empty?

      # Hot by mtime
      Dir.glob(File.join(sessions_dir, '*.jsonl')).each do |path|
        age = (now - File.mtime(path).utc) / 86_400.0
        pins[File.basename(path, '.jsonl')] = true if age <= hot_days
      end

      # Learning gold
      learn_file = File.join(Dir.home, '.pwn', 'learning.jsonl')
      if File.exist?(learn_file)
        File.foreach(learn_file) do |line|
          r = JSON.parse(line, symbolize_names: true)
          sid = r[:session_id].to_s
          next if sid.empty?

          gold = r[:success] == true && (
            !r.key?(:score) || r[:score].to_f >= GOLD_MIN_SCORE
          )
          pins[sid] = true if gold
        rescue StandardError
          next
        end
      end

      # Mistakes refs
      mist_file = File.join(Dir.home, '.pwn', 'mistakes.json')
      if File.exist?(mist_file)
        begin
          store = JSON.parse(File.read(mist_file), symbolize_names: true)
          store.each_value do |m|
            next unless m.is_a?(Hash)

            openish = !m[:resolved] || m[:regressed]
            recent_closed = false
            if m[:resolved] && m[:last_seen]
              begin
                recent_closed = ((now - Time.parse(m[:last_seen].to_s)) / 86_400.0) <= retain_days
              rescue StandardError
                recent_closed = false
              end
            end
            next unless openish || recent_closed

            Array(m[:sessions]).each { |s| pins[s.to_s] = true if s.to_s != '' }
          end
        rescue StandardError
          # ignore
        end
      end

      pins.keys.reject(&:empty?)
    end

    private_class_method def self.stub_session?(opts = {})
      path = opts[:path]
      return true unless File.exist?(path)

      rows = File.readlines(path).map do |l|
        JSON.parse(l, symbolize_names: true)
      rescue StandardError
        nil
      end.compact
      substantive = rows.any? do |e|
        role = e[:role].to_s
        %w[user assistant].include?(role) && e[:content].to_s.strip.length > 20
      end
      !substantive
    rescue StandardError
      true
    end

    private_class_method def self.compact_transcript!(opts = {})
      path = opts[:path]
      tool_max = opts[:tool_max] || TOOL_CONTENT_MAX
      asst_max = opts[:assistant_content_max] || opts[:asst_max] || ASSISTANT_CONTENT_MAX
      dry = opts[:dry_run] ? true : false
      return false unless File.exist?(path)

      lines = File.readlines(path)
      rows = lines.map do |l|
        JSON.parse(l, symbolize_names: true)
      rescue StandardError
        nil
      end.compact
      return false if rows.empty?

      # Preserve last assistant fully-ish; compact tools and older assistants
      last_asst_i = rows.rindex { |e| e[:role].to_s == 'assistant' }
      changed = false
      rows.each_with_index do |e, i|
        role = e[:role].to_s
        content = e[:content].to_s
        if role == 'tool' && content.bytesize > tool_max
          e[:content] = "#{content[0, tool_max]}…[compacted]"
          changed = true
        elsif role == 'assistant' && i != last_asst_i && content.bytesize > asst_max
          e[:content] = "#{content[0, asst_max]}…[compacted]"
          changed = true
        elsif role == 'assistant' && i == last_asst_i && content.bytesize > (asst_max * 2)
          e[:content] = "#{content[0, asst_max * 2]}…[compacted]"
          changed = true
        end
      end
      return changed if dry || !changed

      tmp = "#{path}.#{Process.pid}.tmp"
      File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |f|
        f.flock(File::LOCK_EX)
        rows.each { |e| f.puts(JSON.generate(e)) }
        f.flush
        f.fsync
      end
      File.rename(tmp, path)
      true
    ensure
      FileUtils.rm_f(tmp) if defined?(tmp) && tmp && File.exist?(tmp)
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.export(opts = {})
      sid = opts[:session_id].to_s
      raise 'ERROR: session_id required' if sid.empty?

      src = File.join(sessions_dir, "#{sid}.jsonl")
      raise "Session #{sid} not found" unless File.exist?(src)

      dir = File.join(Dir.home, '.pwn', 'exports')
      FileUtils.mkdir_p(dir)
      dest = File.join(dir, "#{sid}.tar.gz")
      manifest = { File.basename(src) => Digest::SHA256.file(src).hexdigest }
      Dir.mktmpdir do |tmp|
        body = File.read(src)
        body = redact(content: body)
        File.write(File.join(tmp, File.basename(src)), body)
        eng = opts[:engagement_id].to_s
        unless eng.empty? && opts[:engagement] != true
          rendered = PWN::Plugins::Findings.render(dir_path: tmp, report_name: 'findings') if defined?(PWN::Plugins::Findings)
          Array(rendered&.values).each do |p|
            next unless p.to_s != '' && File.file?(p.to_s)

            manifest[File.basename(p)] = Digest::SHA256.file(p).hexdigest
          end
        end
        File.write(File.join(tmp, 'manifest.json'), JSON.generate(manifest))
        system('tar', '-czf', dest, '-C', tmp, '.')
      end
      { path: dest, session_id: sid, manifest: manifest }
    end

    public_class_method def self.retain(opts = {})
      days = (opts[:days] || 90).to_i
      cutoff = Time.now - (days * 86_400)
      gzipped = 0
      Dir[File.join(sessions_dir, '*.jsonl')].each do |path|
        next if File.mtime(path) > cutoff

        lines = File.readlines(path)
        keep = lines.first(20) + lines.last(20)
        Zlib::GzipWriter.open("#{path}.gz") { |gz| gz.write(keep.join) }
        File.delete(path)
        gzipped += 1
      end
      { deleted: 0, gzipped: gzipped, days: days }
    end

    public_class_method def self.redact(opts = {})
      text = opts[:content].to_s
      return text if redact_disabled?

      text = text.gsub(/AKIA[0-9A-Z]{16}/) { |m| redacted_token(kind: 'aws', value: m) }
      text = text.gsub(/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/) { |m| redacted_token(kind: 'jwt', value: m) }
      text = text.gsub(%r{Bearer\s+[A-Za-z0-9._\-+/=]{12,}}i) { |m| redacted_token(kind: 'bearer', value: m) }
      text = text.gsub(/-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----/m) { |m| redacted_token(kind: 'pem', value: m) }
      text = text.gsub(/(password\s*[:=]\s*)\S+/i) { "#{Regexp.last_match(1)}#{redacted_token(kind: 'password', value: Regexp.last_match(0))}" }
      text.gsub(/Set-Cookie:\s*[^\r\n]+/i) { |m| redacted_token(kind: 'cookie', value: m) }
    end

    private_class_method def self.redact_disabled?
      v = (PWN::Env.dig(:ai, :agent, :redact_transcripts) if defined?(PWN::Env))
      v == false
    rescue StandardError
      false
    end

    private_class_method def self.redacted_token(opts = {})
      kind = opts[:kind].to_s
      digest = Digest::SHA256.hexdigest(opts[:value].to_s)[0, 8]
      "[REDACTED:#{kind}:#{digest}]"
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    # Display Usage for this Module
    public_class_method def self.help
      puts "USAGE:
        # Run sessions dir and return its result
        #{self}.sessions_dir

        # Run list and return its result
        #{self}.list

        # Run create and return its result
        #{self}.create(
          title: 'optional - human title',
          source: 'optional - e.g. pwn-ai (defaults to pwn-ai)',
          id: 'optional - fixed session id (tests / replay); default timestamp_hex'
        )

        # Run append and return its result
        #{self}.append(
          session_id: 'required - session id value consumed by #append',
          role: 'optional - user|assistant|system|observation',
          content: 'optional - the message or obs'
        )

        # Run load and return its result
        #{self}.load(
          session_id: 'optional - session id value consumed by #load'
        )

        # Newest session that is not exclude_session_id (the prior pwn-ai run)
        #{self}.previous_id(
          exclude_session_id: 'optional - current session to skip'
        )

        # Search prior session transcripts for query terms. Current session is
        #{self}.recall(
          query: 'optional - substring / tokens to match',
          exclude_session_id: 'optional - skip this id (current session)',
          include_current: 'optional - Boolean include excluded id (default false)',
          limit: 'optional - max hits (default 12)',
          max_files: 'optional - newest files to scan (default 40)',
          truncate: 'optional - chars per hit (default 280)',
          target: 'optional - IP, host, or token that must appear in the hit'
        )

        # Run to response history and return its result
        #{self}.to_response_history(
          session_id: 'optional - session id value consumed by #to_response_history'
        )

        # Current-session conversation for the next LLM call. User + assistant
        #{self}.to_llm_messages(
          session_id: 'optional - session id value consumed by #to_llm_messages',
          max_chars: 'optional - max chars value consumed by #to_llm_messages',
          skip_request: 'optional - skip request value consumed by #to_llm_messages'
        )

        # Refuses deletion of pinned sessions (hot/gold/mistake/current) unless force:true
        #{self}.delete(
          session_id: 'required - session id value consumed by #delete',
          force: 'optional - Boolean bypass pin policy (default false)',
          current_session_id: 'optional - current session id value consumed by #delete'
        )

        # Run stats and return its result
        #{self}.stats

        # Run lean and return its result
        #{self}.lean!(
          dry_run: 'optional - Boolean (default false)',
          retain_days: 'optional - drop unreferenced older than this',
          hot_days: 'optional - always keep newer than this',
          max_files: 'optional - soft file cap after protections',
          current_session_id: 'optional - never delete this id',
          tool_content_max: 'optional - tool content max value consumed by #lean!',
          assistant_content_max: 'optional - assistant content max value consumed by #lean!'
        )

        # Build the pin set from learning gold + open mistakes + hot files + current
        #{self}.protected_session_ids(
          now: 'optional - now value consumed by #protected_session_ids (defaults to Time.now.utc)',
          hot_days: 'optional - hot days value consumed by #protected_session_ids',
          retain_days: 'optional - retain days value consumed by #protected_session_ids',
          current_session_id: 'optional - current session id value consumed by #protected_session_ids'
        )

        # Replace secrets in transcript text with [REDACTED:kind:sha256-8].
        #{self}.redact(
          content: 'required - string to redact before persisting'
        )

        # Pack a session jsonl plus artifacts into ~/.pwn/exports/<id>.tar.gz.
        #{self}.export(
          session_id: 'required - session id to export',
          engagement_id: 'optional - include findings SARIF/md/json in the tarball',
          engagement: 'optional - Boolean include findings even without an id'
        )

        # Delete session jsonl files older than days (defaults to 90).
        #{self}.retain(
          days: 'optional - age in days after which transcripts are removed'
        )

        # Print the AUTHOR(S) string for this module.
        #{self}.authors
      "
      constants.sort
    end
  end
end
