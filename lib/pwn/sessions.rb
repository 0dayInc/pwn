# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'securerandom'
require 'digest'
require 'zlib'
require 'shellwords'
require_relative 'redaction'

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
    TITLE_WORD_MAX = 7
    METADATA_MUTEX = Mutex.new

    SESSION_ID = /\A\d{8}_\d{6}_[0-9a-f]{8}\z/
    # Selectors follow writer-owned schemas only; never recurse through payloads.
    # :values is a documented map, :items an array, :path a session file path.
    DEPENDENCY_SCHEMAS = {
      %r{\A(?:learning\.jsonl|learning/disputed\.jsonl|policy_traj\.jsonl|open_goal\.json|jobs/[0-9a-f]{12}\.json)\z} => [['session_id']],
      /\Amistakes\.json\z/ => [[:values, 'sessions', :items], [:values, 'verified_sessions', :items]],
      /\Afindings\.jsonl\z/ => [['session_id'], ['evidence_paths', :items, :path], ['poc_artifacts', :items, :path]],
      %r{\Aswarm/[^/]+/personas\.json\z} => [[:values]],
      %r{\Aengagements/[^/]+/facts\.jsonl\z} => [['source_session']],
      # Legacy Findings allowed an empty engagement name (root evidence ledger).
      %r{\Aengagements/(?:[^/]+/)?evidence\.jsonl\z} => [['path', :path]],
      %r{\Aengagements/[^/]+/recon/observations\.jsonl\z} => [['evidence_path', :path]],
      %r{\Aartifacts/manifest\.jsonl\z} => [['session'], ['source_path', :path]],
      %r{\Aartifacts/[^/]+/index\.jsonl\z} => [['src', :path]],
      # These stores do not persist session links. In particular checkpoint
      # result, preference meta and solve data are arbitrary tool/model content.
      /\A(?:policy\.json|preferences\.jsonl|reward_sentinel\.json|skill_review\.jsonl|curriculum_kpi\.jsonl)\z/ => [],
      %r{\Aruns/[^/]+/checkpoints\.jsonl\z} => [],
      %r{\Amissions/[^/]+\.json\z} => [],
      %r{\Aswarm/[^/]+/(?:bus\.jsonl|solve\.json)\z} => [],
      %r{\Acurriculum/(?:models|cooldown)\.json\z} => [],
      %r{\Aengagements/[^/]+\.json\z} => [],
      %r{\Aengagements/[^/]+/(?:hosts\.json|scans/nmap-[^/]+\.json|binaries/[^/]+/facts\.json)\z} => [],
      %r{\Aartifacts/[^/]+/engagement-memory\.json\z} => []
    }.freeze

    # Preserve candidate records for machine callers; presentation belongs to REPL.
    class AmbiguousTitle < ArgumentError
      attr_reader :identifier, :candidates

      def initialize(identifier:, candidates:)
        @identifier = identifier
        @candidates = candidates
        super("Ambiguous session title; use an id: #{candidates.map { |row| row[:id] }.join(', ')}")
      end
    end

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
      references = dependency_index
      Dir.glob(File.join(dir, '*.jsonl')).reverse.map do |f|
        naming = title_status(session_id: File.basename(f, '.jsonl'))
        {
          id: File.basename(f, '.jsonl'),
          title: metadata(session_id: File.basename(f, '.jsonl'))[:title],
          dependencies: references[:dependencies].fetch(File.basename(f, '.jsonl'), []),
          dependency_errors: references[:errors],
          path: f,
          size: File.size(f),
          mtime: File.mtime(f).utc.iso8601,
          lines: File.readlines(f).count
        }.merge(naming)
      end
    end

    # Index retained loop evidence without reading vault/config/credential stores.
    # Supported Method Parameters::
    #   references = PWN::Sessions.dependency_index
    # dependencies maps session IDs to files REFERENCING them (not files they
    # depend on). Unknown/malformed stores are errors, never inferred text links.
    public_class_method def self.dependency_index
      root = File.join(Dir.home, '.pwn')
      files = %w[learning.jsonl learning/disputed.jsonl mistakes.json memory.json memory.archive.json open_goal.json
                 policy.json policy_traj.jsonl preferences.jsonl reward_sentinel.json
                 skill_review.jsonl curriculum_kpi.jsonl extrospection.json findings.jsonl].map { |name| File.join(root, name) }
      directories = %w[runs missions jobs swarm curriculum engagements].map { |name| File.join(root, name) } + [SESSIONS_DIR]
      errors = directories.select { |dir| File.symlink?(dir) || (File.exist?(dir) && !File.directory?(dir)) }
      files.concat(Dir.glob(File.join(root, 'artifacts', '{manifest.jsonl,*/index.jsonl,*/engagement-memory.json}')))
      databases = Dir.glob(File.join(root, 'embeddings', '*.db'))
      errors.concat(%w[artifacts embeddings].map { |name| File.join(root, name) }.select { |dir| File.symlink?(dir) || (File.exist?(dir) && !File.directory?(dir)) })
      directories.each do |dir|
        next unless File.directory?(dir) && !File.symlink?(dir)

        files.concat(Dir.glob(File.join(dir, '**', '*.{json,jsonl}')).reject { |path| File.basename(path) == 'loot.json' })
        errors.concat(Dir.glob(File.join(dir, '**', '*')).select { |path| File.symlink?(path) })
      end
      dependencies = {}
      evidence_dependencies = {}
      databases.each do |path|
        id = File.basename(path, '.db')
        next unless id.match?(SESSION_ID)

        raise IOError, 'Unsafe embedding store' unless File.file?(path) && File.realpath(path) == File.expand_path(path)

        dependencies[id] = [path]
      rescue IOError, SystemCallError
        errors << path
      end
      files.uniq.sort.each do |path|
        next unless File.exist?(path) || File.symlink?(path)

        begin
          raise IOError, 'Unsafe dependency parent' if errors.any? { |parent| path.start_with?("#{parent}/") }
          raise IOError, 'Unsafe dependency store' unless File.file?(path) && File.realpath(path) == File.expand_path(path)

          records = path.end_with?('.jsonl') ? File.foreach(path).map { |line| JSON.parse(line) } : [JSON.parse(File.read(path))]
          raise IOError, 'Invalid dependency records' unless records.all?(Hash)
          raise IOError, 'Invalid mistake entries' if path == File.join(root, 'mistakes.json') && !records.first.values.all?(Hash)

          if path == File.join(root, 'learning.jsonl')
            records.each do |record|
              next unless record.key?('evidence_ref')

              begin
                PWN::AI::Agent::Learning.evidence_transcript(row: record)
                hash = record['evidence_ref']['sha256']
                evidence_dependencies[File.join(root, 'learning', 'evidence', "#{hash}.json")] = [path]
              rescue IOError
                errors << path
              end
            end
          end

          dependency_ids(path: path, root: root, records: records).uniq.each do |id|
            (dependencies[id] ||= []) << path
          end
        rescue JSON::ParserError, IOError, SystemCallError
          errors << path
        end
      end
      result = { dependencies: dependencies.transform_values { |paths| paths.uniq.sort }, errors: errors.uniq.sort }
      result[:evidence_dependencies] = evidence_dependencies unless evidence_dependencies.empty?
      result
    end

    private_class_method def self.dependency_ids(opts = {})
      path = opts[:path]
      records = opts[:records]
      if path.start_with?("#{SESSIONS_DIR}/")
        relative = path.delete_prefix("#{SESSIONS_DIR}/")
        # There is no cross-session link in the transcript/sidecar schema.
        return [] if relative.match?(%r{\A[^/]+\.(?:jsonl|meta\.json)\z})
        return dependency_value(value: relative.split('/').first) if relative.match?(%r{\A[^/]+/trace\.jsonl\z})

        raise IOError, 'Unknown session dependency store'
      end

      relative = path.delete_prefix("#{opts[:root]}/")
      return memory_dependency_ids(records: records) if %w[memory.json memory.archive.json].include?(relative)
      return event_dependency_ids(name: relative, records: records) if %w[curriculum/log.jsonl extrospection.json].include?(relative)

      schema = DEPENDENCY_SCHEMAS.find { |pattern, _| relative.match?(pattern) }
      raise IOError, 'Unknown dependency store' unless schema

      ids = records.flat_map do |record|
        next [] if relative == 'learning.jsonl' && record.key?('evidence_ref') && PWN::AI::Agent::Learning.evidence_complete?(row: record)

        # Swarm.bus_append passes a swarm ID through ArtifactRegistry's session
        # parameter. Its kind disambiguates that namespace, even on a collision.
        record = record.except('session') if relative == 'artifacts/manifest.jsonl' && record['kind'] == 'swarm-bus'
        schema.last.flat_map { |selector| dependency_select(value: record, selector: selector) }
      end
      # ArtifactRegistry and EngagementMemory explicitly scope these paths by
      # session; arbitrary filenames, swarm IDs and run IDs are not session IDs.
      ids.concat(dependency_value(value: relative.split('/')[1])) if relative.match?(%r{\Aartifacts/[^/]+/(?:index\.jsonl|engagement-memory\.json)\z})
      ids
    end

    private_class_method def self.dependency_select(opts = {})
      value = opts[:value]
      selector = opts[:selector]
      return [] if value.nil?
      return dependency_value(value: value) if selector.empty?

      key, *rest = selector
      case key
      when :values, :items
        type = key == :values ? Hash : Array
        raise IOError, 'Invalid dependency container' unless value.is_a?(type)

        values = key == :values ? value.values : value
        values.flat_map { |item| dependency_select(value: item, selector: rest) }
      when :path
        raise IOError, 'Invalid dependency path' unless value.is_a?(String)
        return [] unless File.dirname(value) == SESSIONS_DIR && value.match?(/\.(?:meta\.json|jsonl)\z/)

        dependency_value(value: File.basename(value).sub(/\.(?:meta\.json|jsonl)\z/, ''))
      else
        raise IOError, 'Invalid dependency object' unless value.is_a?(Hash)

        dependency_select(value: value[key], selector: rest)
      end
    end

    private_class_method def self.dependency_value(opts = {})
      value = opts[:value]
      return [] if value.nil?
      raise IOError, 'Invalid session reference' unless value.is_a?(String)

      value.match?(SESSION_ID) ? [value] : []
    end

    private_class_method def self.memory_dependency_ids(opts = {})
      opts[:records].flat_map do |record|
        raise IOError, 'Invalid memory entries' unless record.values.all?(Hash)

        # Learning.reflect's durable key is reflect_<session>_<lesson digest>.
        # Memory values, sources and arbitrary user-selected keys are not links.
        record.keys.filter_map { |key| key[/\Areflect_(\d{8}_\d{6}_[0-9a-f]{8})_[0-9a-f]{8}\z/, 1] }
      end
    end

    private_class_method def self.event_dependency_ids(opts = {})
      opts[:records].flat_map do |record|
        if opts[:name] == 'curriculum/log.jsonl'
          # Curriculum.practice persists run results only for this event.
          next [] unless record['event'] == 'practice'

          dependency_select(value: record, selector: ['data', :items, 'runs', :items, 'session_id'])
        else
          observations = record.fetch('observations', [])
          raise IOError, 'Invalid extrospection observations' unless observations.is_a?(Array) && observations.all?(Hash)

          observations.flat_map do |observation|
            # auto_extrospect writes ['drift', session_id]; other tags are free text.
            next [] unless observation['source'] == 'auto_extrospect'

            tags = observation.fetch('tags', [])
            raise IOError, 'Invalid extrospection tags' unless tags.is_a?(Array)
            next [] unless tags.first == 'drift'

            dependency_value(value: tags[1])
          end
        end
      end
    end

    # Hold a kernel-owned shared lease until the caller closes this handle.
    # Cleanup takes an exclusive lock on this same permanent inode. No PID or
    # timestamp can grant ownership; exit/crash closes the actual descriptor.
    # Supported Method Parameters::
    #   lease = PWN::Sessions.activate(session_id: 'required - stable transcript identifier for activity ownership', creating: 'optional - allow creation under the lease')
    public_class_method def self.activate(opts = {})
      sid = opts[:session_id].to_s
      raise ArgumentError, 'Invalid session ID' if sid.empty? || File.basename(sid) != sid || sid.include?("\0") || sid == '.' || sid == '..'

      register_activity_owner
      lock = File.open(File.join(sessions_dir, ".#{sid}.cleanup.lock"), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) # rubocop:disable Style/FileOpen -- caller owns the lease lifetime
      lock.close_on_exec = true
      raise IOError, "Session #{sid} is being removed" unless lock.flock(File::LOCK_SH | File::LOCK_NB)
      raise IOError, "Session #{sid} not found" unless opts[:creating] || File.file?(File.join(sessions_dir, "#{sid}.jsonl"))

      lock
    rescue Exception # rubocop:disable Lint/RescueException -- interrupts must close untransferred lease descriptors
      lock&.close
      raise
    end

    # Closing, not LOCK_UN, preserves independent and inherited owners.
    # Supported Method Parameters::
    #   PWN::Sessions.deactivate(lease: 'required - handle returned by activate')
    public_class_method def self.deactivate(opts = {})
      lease = opts[:lease]
      lease.close if lease && !lease.closed?
      nil
    end

    # A held capability marker distinguishes upgraded idle launchers from legacy
    # processes with unknowable in-memory ownership. This is NOT a session pin.
    private_class_method def self.register_activity_owner
      return unless File.file?('/proc/self/stat')

      start = File.read('/proc/self/stat').split(') ').last.split[19]
      path = File.join(sessions_dir, ".activity-owner-#{Process.pid}-#{start}.lock")
      @activity_owner_mutex ||= Mutex.new
      @activity_owner_mutex.synchronize do
        @activity_owners ||= {}
        @activity_owners.delete_if do |owner_path, handle|
          expired = !File.exist?(owner_path) || !owner_path.include?(".activity-owner-#{Process.pid}-")
          handle.close if expired && !handle.closed?
          expired
        end
        return if @activity_owners[path] && !@activity_owners[path].closed?

        marker = File.open(path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) # rubocop:disable Style/FileOpen -- process-lifetime capability marker
        marker.close_on_exec = true
        raise IOError, 'Activity owner marker already locked' unless marker.flock(File::LOCK_EX | File::LOCK_NB)

        @activity_owners[path] = marker
      end
      nil
    end

    # Probe kernel ownership without trusting stale marker contents.
    # Supported Method Parameters::
    #   active = PWN::Sessions.active?(session_id: 'required - stable transcript identifier for activity ownership')
    public_class_method def self.active?(opts = {})
      sid = opts[:session_id].to_s
      raise ArgumentError, 'Invalid session ID' if sid.empty? || File.basename(sid) != sid || sid == '.' || sid == '..'

      File.open(File.join(sessions_dir, ".#{sid}.cleanup.lock"), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
        !lock.flock(File::LOCK_EX | File::LOCK_NB)
      end
    end

    # Supported Method Parameters::
    #   session = PWN::Sessions.create(
    #     title: 'optional - human title, capped at seven whitespace-separated words',
    #     source: 'optional - e.g. pwn-ai',
    #     id: 'optional - fixed session id (tests / replay); default timestamp_hex',
    #     active: 'optional - return an owned lease with the new session'
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
      lease = activate(session_id: id, creating: true)
      raise "Session #{id} already exists" if File.exist?(path)

      meta = {
        id: id,
        title: bounded_title(title: opts[:title] || "pwn-ai session #{id}"),
        source: opts[:source] || 'pwn-ai',
        created_at: Time.now.utc.iso8601
      }

      meta = PWN::Redaction.redact(value: meta)
      File.open(path, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |f|
        f.puts(JSON.dump(role: 'system', content: "Session started: #{meta[:title]}", timestamp: meta[:created_at]))
      end
      write_metadata(session_id: id, metadata: meta)
      result = { id: id, path: path, meta: meta }
      result[:lease] = lease if opts[:active]
      result
    ensure
      deactivate(lease: lease) unless result && opts[:active]
    end

    # Read durable session naming metadata, including legacy transcript titles.
    # Normalize old titles without rewriting files; list, resume and panes share
    # this effective title. Explicit titles follow the same seven-word limit.
    public_class_method def self.metadata(opts = {})
      sid = opts[:session_id].to_s
      path = File.join(sessions_dir, "#{sid}.meta.json")
      if File.file?(path)
        stored = JSON.parse(File.read(path), symbolize_names: true)
        return stored.merge(id: sid, title: bounded_title(title: stored[:title])) if stored.is_a?(Hash) && !bounded_title(title: stored[:title]).empty?
      end

      first = File.open(File.join(sessions_dir, "#{sid}.jsonl"), &:gets)
      row = JSON.parse(first.to_s, symbolize_names: true)
      title = row[:content].to_s.delete_prefix('Session started: ') if row[:role] == 'system' && row[:content].to_s.start_with?('Session started: ')
      { id: sid, title: bounded_title(title: title.to_s.empty? ? "pwn-ai session #{sid}" : title) }
    rescue Errno::ENOENT, JSON::ParserError
      { id: sid, title: bounded_title(title: "pwn-ai session #{sid}") }
    end

    # Read strict persisted title provenance, never infer LLM work from title text.
    # Supported Method Parameters::
    #   status = PWN::Sessions.title_status(session_id: 'required - canonical session ID')
    public_class_method def self.title_status(opts = {})
      sid = opts[:session_id].to_s
      status = { title_source: nil, is_summarized: false, classification: :unknown, title_reason: 'invalid_session' }
      return status unless sid.match?(SESSION_ID)

      path = File.join(sessions_dir, "#{sid}.jsonl")
      return status.merge(title_reason: 'invalid_transcript') unless cleanup_transcript_valid?(path: path)

      meta_path = path.sub(/\.jsonl\z/, '.meta.json')
      return status.merge(classification: :unnamed, title_reason: 'missing_summary_provenance') unless File.exist?(meta_path) || File.symlink?(meta_path)
      return status.merge(title_reason: 'unsafe_metadata') unless File.file?(meta_path) && !File.symlink?(meta_path)

      meta = JSON.parse(File.read(meta_path))
      return status.merge(title_reason: 'invalid_metadata') unless meta.is_a?(Hash)

      status[:title_source] = meta['title_source']
      keys = %w[id title source created_at updated_at title_source title_aliases title_history summary summary_turns]
      valid = (meta.keys - keys).empty? && meta['title'].is_a?(String) && !bounded_title(title: meta['title']).empty?
      valid &&= !meta.key?('id') || meta['id'] == sid
      valid &&= !meta.key?('source') || %w[pwn-ai pwn-ai-cli pwn-ai-swarm].include?(meta['source'])
      valid &&= !meta.key?('summary') || meta['summary'].is_a?(String)
      valid &&= !meta.key?('summary_turns') || (meta['summary_turns'].is_a?(Integer) && meta['summary_turns'] >= 0)
      valid &&= %w[title_aliases title_history].all? { |key| !meta.key?(key) || (meta[key].is_a?(Array) && meta[key].all?(String)) }
      return status.merge(title_reason: 'invalid_metadata') unless valid

      case meta['title_source']
      when 'summary'
        return status.merge(title_reason: 'incomplete_summary_provenance') unless meta['summary'].is_a?(String) && !meta['summary'].match?(/\A[[:space:]]*\z/) && meta['summary_turns'].is_a?(Integer) && meta['summary_turns'].positive?
        return status.merge(classification: :unnamed, title_reason: 'placeholder_not_summary') unless summary_title_valid?(title: meta['title'])

        status.merge(is_summarized: true, classification: :named, title_reason: 'llm_summary')
      when 'provisional', 'manual', nil, ''
        reason = %w[provisional manual].include?(meta['title_source']) ? "#{meta['title_source']}_not_summary" : 'missing_summary_provenance'
        status.merge(classification: :unnamed, title_reason: reason)
      else
        status.merge(title_reason: 'unknown_title_source')
      end
    rescue JSON::ParserError, IOError, SystemCallError, ArgumentError
      status.merge(title_reason: 'unreadable_metadata')
    end

    # Reject default identifiers even if a provider echoes one as its title.
    private_class_method def self.summary_title_valid?(opts = {})
      title = bounded_title(title: opts[:title]).strip
      !title.empty? && !title.match?(/\Apwn-ai(?: session \d{8}_\d{6}_[a-f0-9]{8}| \d{4}-\d{2}-\d{2} \d{2}:\d{2})?\z/)
    end

    # Structural deletion guard shared by listing and scheduled cleanup.
    private_class_method def self.cleanup_transcript_valid?(opts = {})
      path = opts[:path]
      return false unless File.file?(path) && !File.symlink?(path)

      rows = File.foreach(path).map { |line| JSON.parse(line) }
      return false if rows.empty? || rows.any? { |row| !row.is_a?(Hash) || !%w[system user assistant tool observation].include?(row['role']) || !row.key?('content') }

      first = rows.first
      return false unless first['role'] == 'system' && first['content'].is_a?(String) && first['content'].start_with?('Session started: ')

      rows.all? do |row|
        (row.keys - %w[role content timestamp title step_reward]).empty? &&
          (!row.key?('title') || row['title'].is_a?(String)) &&
          (!row.key?('step_reward') || (row['role'] == 'tool' && row['step_reward'].is_a?(Integer) && [-1, 0, 1].include?(row['step_reward'])))
      end
    rescue JSON::ParserError, IOError, SystemCallError
      false
    end

    # Resolve an exact id first, then a unique current or previously displayed title.
    # A background summary must not invalidate a name just copied from the menu.
    public_class_method def self.resolve(opts = {})
      identifier = opts[:identifier].to_s
      rows = list
      return identifier if rows.any? { |row| row[:id] == identifier }

      titles = rows.to_h do |row|
        aliases = Array(metadata(session_id: row[:id])[:title_aliases]).map { |title| bounded_title(title: title) }.reject(&:empty?)
        [row[:id], [row[:title]] + aliases]
      end
      matches = rows.select { |row| titles[row[:id]].include?(identifier) }
      if matches.empty? && identifier.match?(/\A(["']).*\1\z/m)
        unquoted = Shellwords.shellsplit(identifier)
        if unquoted.length == 1
          return unquoted.first if rows.any? { |row| row[:id] == unquoted.first }

          matches = rows.select { |row| titles[row[:id]].include?(unquoted.first) }
        end
      end
      raise AmbiguousTitle.new(identifier: identifier, candidates: matches) if matches.length > 1
      raise ArgumentError, "Session #{identifier.inspect} not found" if matches.empty?

      matches.first[:id]
    end

    # Seed a local provisional title before any provider work begins.
    public_class_method def self.provisional_title(opts = {})
      sid = opts[:session_id].to_s
      text = bounded_title(title: PWN::Redaction.redact(value: opts[:request].to_s).gsub(/[[:space:][:cntrl:]]+/, ' '))
      METADATA_MUTEX.synchronize do
        meta = metadata(session_id: sid)
        if !text.empty? && meta[:title] == "pwn-ai session #{sid}"
          meta = meta.merge(title: text, title_source: 'provisional')
          write_metadata(session_id: sid, metadata: meta)
        end
        meta
      end
    end

    # Summarize newly persisted turns into a rolling overall conversation summary.
    # Call from a worker, never the terminal/input thread. Failed summaries retain
    # the provisional/previous title and leave the cursor available for retry.
    public_class_method def self.refresh_title(opts = {})
      sid = opts[:session_id].to_s
      lease = activate(session_id: sid)
      original = metadata(session_id: sid)
      rows = load(session_id: sid).select { |row| %w[user assistant].include?(row[:role].to_s) }
      cursor = original[:summary_turns].to_i
      return original if rows.length <= cursor

      result = original
      text = rows.drop(cursor).map { |row| "#{row[:role]}: #{row[:content]}" }.join("\n")
      # Character chunks keep Unicode intact, including four-byte characters.
      text.chars.each_slice(1500) do |chunk|
        output = PWN::AI::Router.summarize(text: "Previous overall summary: #{result[:summary]}\nNew conversation turns:\n#{chunk.join}", llm: true, session: true)
        parsed = JSON.parse(output.to_s.sub(/\A```(?:json)?\s*/, '').sub(/\s*```\z/, ''), symbolize_names: true)
        return original unless parsed.is_a?(Hash) && parsed[:title].is_a?(String) && parsed[:summary].is_a?(String)
        return original if !summary_title_valid?(title: parsed[:title]) || parsed[:summary].strip.empty?

        result = result.merge(title: bounded_title(title: parsed[:title].gsub(/[[:space:][:cntrl:]]+/, ' ')), summary: parsed[:summary])
      end
      METADATA_MUTEX.synchronize do
        current = metadata(session_id: sid)
        return current unless current[:summary_turns].to_i == cursor

        result = result.merge(title_aliases: (Array(current[:title_aliases]) + [current[:title]]).uniq) unless result[:title] == current[:title]
        result = PWN::Redaction.redact(value: result.merge(summary_turns: rows.length, title_source: 'summary', updated_at: Time.now.utc.iso8601))
        write_metadata(session_id: sid, metadata: result)
        result
      end
    rescue StandardError
      original
    ensure
      deactivate(lease: lease)
    end

    # Bound titles only, retaining internal whitespace and quotes for exact resume.
    private_class_method def self.bounded_title(opts = {})
      text = opts[:title].to_s.gsub(/[[:cntrl:]]/, ' ').sub(/\A[[:space:]]+/, '')
      text[/\A[^[:space:]]+(?:[[:space:]]+[^[:space:]]+){0,#{TITLE_WORD_MAX - 1}}/].to_s
    end

    private_class_method def self.write_metadata(opts = {})
      sid = opts[:session_id].to_s
      lease = activate(session_id: sid)
      path = File.join(sessions_dir, "#{sid}.meta.json")
      return unless File.file?(File.join(sessions_dir, "#{sid}.jsonl"))

      tmp = "#{path}.#{SecureRandom.hex(8)}.tmp"
      File.open(tmp, File::WRONLY | File::CREAT | File::EXCL, 0o600) do |file|
        file.write(JSON.generate(PWN::Redaction.redact(value: opts[:metadata])))
        file.flush
        file.fsync
      end
      File.rename(tmp, path)
    ensure
      FileUtils.rm_f(tmp) if tmp
      deactivate(lease: lease)
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

      lease = activate(session_id: sid)
      path = File.join(sessions_dir, "#{sid}.jsonl")
      raise "Session #{sid} not found" unless File.exist?(path)

      role = (opts[:role] || 'user').to_s
      raw = opts[:content]
      PWN::Redaction.capture(value: raw, vault: true) if raw.is_a?(String) && %w[tool observation].include?(role)
      content = PWN::Redaction.redact(value: raw)
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
      content = PWN::AI::Agent::Result.utf8_value(value: content) if content.is_a?(String) || content.is_a?(Hash) || content.is_a?(Array)
      entry = {
        role: redact(content: role),
        content: content,
        timestamp: Time.now.utc.iso8601
      }
      File.open(path, 'a') { |f| f.puts(JSON.dump(entry)) }
      provisional_title(session_id: sid, request: content) if role == 'user'
      entry
    ensure
      deactivate(lease: lease)
    end

    # Supported Method Parameters::
    #   transcript = PWN::Sessions.load(session_id: 'required')
    public_class_method def self.load(opts = {})
      sid = opts[:session_id]
      path = File.join(sessions_dir, "#{sid}.jsonl")
      return PWN::AI::Agent::Learning.session_evidence(session_id: sid) || [] unless File.exist?(path)

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
          if body.include?('[compacted') && body =~ /ref=(\S+)/
            ref = Regexp.last_match(1)
            body = File.read(ref) if File.file?(ref)
          end
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
    public_class_method def self.delete(opts = {})
      sid = opts[:session_id].to_s
      raise 'ERROR: session_id required' if sid.to_s.empty?
      raise ArgumentError, 'Invalid session ID' if File.basename(sid) != sid || sid.include?("\0") || sid == '.' || sid == '..'

      force = opts[:force] ? true : false
      path = File.join(sessions_dir, "#{sid}.jsonl")
      lock_path = File.join(sessions_dir, ".#{sid}.cleanup.lock")
      lock = opts[:cleanup_lock] || File.open(lock_path, File::RDWR | File::CREAT | File::NOFOLLOW, 0o600)
      raise IOError, "Session #{sid} is active" unless File.identical?(lock, lock_path) && lock.flock(File::LOCK_EX | File::LOCK_NB)

      unless force
        pins = protected_session_ids(current_session_id: opts[:current_session_id])
        raise "ERROR: refusing to delete protected session #{sid.inspect} (pinned by HOT_DAYS/gold/mistakes/current; pass force:true)" if pins.include?(sid.to_s)
      end

      FileUtils.rm_f(path)
      FileUtils.rm_f(File.join(sessions_dir, "#{sid}.meta.json"))
      true
    ensure
      lock&.close unless opts[:cleanup_lock]
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
        FileUtils.rm_f([e[:path], File.join(dir, "#{e[:id]}.meta.json")]) unless dry
      end

      # Refresh remaining after deletes
      remaining = entries.reject { |e| deleted.include?(e[:id]) }

      # Enforce max_files on unpinned oldest-first
      if remaining.size > max_files
        unpinned = remaining.reject { |e| e[:pinned] }.sort_by { |e| e[:mtime] }
        over = remaining.size - max_files
        unpinned.first(over).each do |e|
          deleted << e[:id]
          FileUtils.rm_f([e[:path], File.join(dir, "#{e[:id]}.meta.json")]) unless dry
          remaining.delete(e)
        end
      end

      # Compact large/cold kept files
      remaining.each do |e|
        next if e[:pinned]
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
      references = dependency_index
      references[:dependencies].each_key { |id| pins[id] = true }
      Dir.glob(File.join(SESSIONS_DIR, '*.jsonl')).each { |path| pins[File.basename(path, '.jsonl')] = true } if references[:errors].any?
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
          next if r.key?(:evidence_ref) && PWN::AI::Agent::Learning.evidence_complete?(row: r)

          gold = r[:success] == true && (
            !r.key?(:score) || r[:score].to_f >= GOLD_MIN_SCORE
          )
          pins[sid] = true if gold || r.key?(:evidence_ref)
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

      lease = activate(session_id: File.basename(path, '.jsonl'))
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
        clean = PWN::Redaction.redact(value: e)
        changed = true if clean != e
        e.replace(clean)
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
      File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |f|
        f.flock(File::LOCK_EX)
        rows.each { |e| f.puts(JSON.generate(e)) }
        f.flush
        f.fsync
      end
      File.rename(tmp, path)
      true
    ensure
      FileUtils.rm_f(tmp) if defined?(tmp) && tmp && File.exist?(tmp)
      deactivate(lease: lease)
    end

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.export(opts = {})
      sid = opts[:session_id].to_s
      raise 'ERROR: session_id required' if sid.empty?

      src = File.join(sessions_dir, "#{sid}.jsonl")
      transcript = load(session_id: sid)
      raise "Session #{sid} not found" if transcript.empty? && !File.exist?(src)

      dir = File.join(Dir.home, '.pwn', 'exports')
      FileUtils.mkdir_p(dir)
      dest = File.join(dir, "#{sid}.tar.gz")
      manifest = {}
      Dir.mktmpdir do |tmp|
        lines = transcript.map { |row| JSON.generate(PWN::Redaction.redact(value: row)) }
        body = "#{lines.join("\n")}\n"
        manifest[File.basename(src)] = Digest::SHA256.hexdigest(body)
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
      pins = protected_session_ids(hot_days: 0)
      Dir[File.join(sessions_dir, '*.jsonl')].each do |path|
        next if pins.include?(File.basename(path, '.jsonl'))
        next if File.mtime(path) > cutoff

        id = File.basename(path, '.jsonl')
        File.open(File.join(sessions_dir, ".#{id}.cleanup.lock"), File::RDWR | File::CREAT | File::NOFOLLOW, 0o600) do |lock|
          next unless lock.flock(File::LOCK_EX | File::LOCK_NB)
          next unless File.file?(path) && File.mtime(path) <= cutoff

          lines = File.readlines(path)
          keep = lines.first(20) + lines.last(20)
          Zlib::GzipWriter.open("#{path}.gz") do |gz|
            keep.each { |line| gz.write("#{JSON.generate(PWN::Redaction.redact(value: JSON.parse(line)))}\n") }
          end
          File.delete(path)
          gzipped += 1
        end
      end
      { deleted: 0, gzipped: gzipped, days: days }
    end

    public_class_method def self.redact(opts = {})
      PWN::Redaction.redact(value: opts[:content])
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

        # Index exact dependency file paths and uncertain stores for cleanup and listing.
        #{self}.dependency_index

        # Hold a shared per-session OS lease until deactivate or process exit.
        #{self}.activate(
          session_id: 'required - stable transcript identifier for activity ownership',
          creating: 'optional - allow creation under the lease; default false'
        )

        # Release exactly the supplied lease, preserving other owners.
        #{self}.deactivate(lease: 'required - handle returned by activate')

        # Probe kernel lease ownership, ignoring stale marker contents.
        #{self}.active?(session_id: 'required - stable transcript identifier for activity ownership')

        # Run create and return its result
        #{self}.create(
          title: 'optional - human title, capped at seven whitespace-separated words',
          source: 'optional - e.g. pwn-ai (defaults to pwn-ai)',
          id: 'optional - fixed session id (tests / replay); default timestamp_hex',
          active: 'optional - return an owned lease with the new session; default false'
        )

        # Run append and return its result
        #{self}.metadata(session_id: 'required - stable session id')

        # Classify strict persisted LLM title provenance without provider calls.
        #{self}.title_status(session_id: 'required - canonical session ID')

        # Resolve a unique exact title or stable id.
        #{self}.resolve(identifier: 'required - exact session title or id')

        # Seed a title from the first submitted request without provider calls.
        #{self}.provisional_title(
          session_id: 'required - stable session id',
          request: 'required - first submitted request'
        )

        # Update a rolling conversation summary and title off the input thread.
        #{self}.refresh_title(session_id: 'required - stable session id to summarize')

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
          current_session_id: 'optional - current session id value consumed by #delete',
          cleanup_lock: 'optional - already-held per-session exclusive cleanup lock'
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
