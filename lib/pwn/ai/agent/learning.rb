# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'digest'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Learning is the self-improvement engine that closes
      # the pwn-ai feedback loop. It captures task outcomes, mines session
      # transcripts for durable lessons, promotes successful workflows into
      # reusable skills, and keeps ~/.pwn lean (memory + learning.jsonl +
      # mistakes + sessions) so the agent gets sharper over time instead of
      # accumulating noise.
      #
      # Data flows:
      #   Loop.run --(tool telemetry)--> Metrics.record
      #   Loop.run --(final answer)----> Learning.auto_introspect (opt-in)
      #     auto_introspect --(throttled)--> Learning.gc_stores!  # ~/.pwn lean
      #   model    --(tool calls)------> learning_note_outcome / _distill_skill
      #   PromptBuilder <----------------- Learning.to_context + Metrics.to_context
      #
      # Everything is file-backed under ~/.pwn so it survives across REPL
      # restarts and is shared by every future session.
      module Learning
        LEARNING_FILE      = File.join(Dir.home, '.pwn', 'learning.jsonl')
        FINETUNE_DIR       = File.join(Dir.home, '.pwn', 'finetune')
        # P0 — post-answer introspect must not train "stop early" while
        # spending the iteration budget after the final. Soft cap skips
        # expensive stages (tool critic, PRM-LLM, reflect, extrospect);
        # hard cap keeps only note_outcome + judge(heuristic) + sentinel.
        INTROSPECT_SOFT_MS = 2_500
        INTROSPECT_HARD_MS = 8_000
        INTROSPECT_MIN_STAGES = %i[judge note_outcome fold_judge sentinel].freeze

        MAX_MEMORY_ENTRIES = 200
        # Lean outcome retention — keep gold RL signal, drop bulk auto noise.
        MAX_OUTCOME_ROWS = 800
        OUTCOME_RETAIN_DAYS = 45
        OUTCOME_RECENT_DAYS = 14
        OUTCOME_DETAILS_MAX = 800
        GOLD_MIN_SCORE = 0.6
        EXEMPLARS_POOL_MIN = 200
        FAILURE_WINDOW_MIN = 200
        HIGH_VALUE_TAGS = %w[
          needs_human extro_verify sdr gqrx rl pwn-ai curriculum hindsight her
        ].freeze
        LOW_VALUE_ONLY_TAGS = %w[
          auto loop partial wrong solved offline_judge plan_cover_high
        ].freeze
        PRUNE_EVERY_N_APPENDS = 25

        # E3/P26 — only CVE-ids or software-name + full semver (x.y.z).
        # Two-part floats ("cap 0.2", "proxy 1.0", "judge 37.0") are RL
        # metric crumbs that were scraped by verify_as_reward and flooded
        # learning.jsonl with extro_verify :unknown failures.
        CLAIM_METRIC_WORDS = %w[
          cap share proxy judge success only now clears gap score rate mean
          brier overconf distrust trajectory_fraction handler orm prm delta
          limit window pct percent ms iter budget conf confidence n
          ruby python linux kernel host cwd e.g e.g.
        ].freeze
        CLAIM_RX = /
          CVE-\d{4}-\d{4,7}
          |
          \b
          (?!
            (?:cap|share|proxy|judge|success|only|now|clears|gap|score|rate|mean|
               brier|overconf|distrust|trajectory_fraction|handler|orm|prm|delta|
               limit|window|pct|percent|ms|iter|budget|conf|confidence|
               ruby|python|linux|kernel|host|cwd|e\.g)
            \b
          )
          [A-Za-z][\w.+-]{2,}
          \s+
          v?\d+\.\d+\.\d+(?:[-+][\w.]+)?
          \b
        /x

        # Supported Method Parameters::
        # entry = PWN::AI::Agent::Learning.note_outcome(
        #   task: 'required - short description of what was attempted',
        #   success: 'required - Boolean, did the attempt achieve its goal',
        #   details: 'optional - free-form notes / error / evidence',
        #   session_id: 'optional - PWN::Sessions id this outcome belongs to',
        #   tags: 'optional - Array of String labels for later retrieval'
        # )

        public_class_method def self.note_outcome(opts = {})
          task    = opts[:task].to_s
          # 4.1 — allow success: 'soft' (HER) distinct from true/false
          raw_ok  = opts[:success]
          success = if ['soft', :soft].include?(raw_ok)
                      'soft'
                    else
                      raw_ok ? true : false
                    end
          raise 'ERROR: task is required' if task.strip.empty?

          tags = Array(opts[:tags]).map(&:to_s)
          details = opts[:details].to_s[0, OUTCOME_DETAILS_MAX]
          # Refuse solved-at-fail (and the reverse): when a score is present,
          # tags / details / boolean success must match verdict_for_score.
          # Soft HER stays soft so C3 positives are not flipped to true/false.
          if opts.key?(:score)
            score = opts[:score].to_f
            want = verdict_for_score(score: score).to_s
            tags = (tags - %w[solved partial wrong unknown]) << want
            details = details.sub(
              /\A(solved|partial|wrong|unknown)\(\d+(?:\.\d+)?\)/i,
              "#{want}(#{format('%.2f', score)})"
            )
            success = (score >= 0.6) if [true, false].include?(success)
          end

          entry = {
            id: Digest::SHA256.hexdigest("#{task}-#{Time.now.to_f}")[0, 12],
            task: task,
            success: success,
            details: details,
            session_id: opts[:session_id],
            tags: tags,
            timestamp: Time.now.utc.iso8601
          }
          entry[:score] = opts[:score].to_f if opts.key?(:score)
          src = opts[:judge_source].to_s
          entry[:judge_source] = src unless src.empty?
          FileUtils.mkdir_p(File.dirname(LEARNING_FILE))
          File.open(LEARNING_FILE, 'a') { |f| f.puts(JSON.generate(entry)) }
          maybe_prune_outcomes!

          # M4 — default: outcomes live in learning.jsonl ONLY.
          # M4.1 — PROCESS SOPs (rubocop/rake/spec after code changes, etc.)
          # are promoted into PWN::Memory[:lesson] so PromptBuilder recall
          # survives across sessions. Without this, the agent re-learns
          # "run rubocop after every patch" every turn (empty memory.json).
          promote_process_lesson(entry: entry) if defined?(PWN::Memory)
          if opts.key?(:score) && defined?(Curriculum) && Curriculum.respond_to?(:calibrate)
            pred = opts[:predicted]
            pred = Thread.current[:pwn_plan_predicted] if pred.nil?
            pred = opts[:confidence] if pred.nil?
            eng = opts[:engine]
            eng = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)) if eng.to_s.empty?
            Curriculum.calibrate(predicted: pred, actual: opts[:score], engine: eng)
          end
          entry
        end

        # Supported Method Parameters::
        # rows = PWN::AI::Agent::Learning.outcomes(
        #   limit: 'optional - max entries returned newest-first (default 50)',
        #   success: 'optional - filter by Boolean outcome',
        #   tag: 'optional - filter by tag substring'
        # )

        public_class_method def self.outcomes(opts = {})
          limit   = opts[:limit] || 50
          want_ok = opts.key?(:success) ? !opts[:success].nil? && opts[:success] != false : nil
          tag     = opts[:tag].to_s.downcase
          return [] unless File.exist?(LEARNING_FILE)

          rows = File.readlines(LEARNING_FILE).map do |l|
            JSON.parse(l, symbolize_names: true)
          rescue StandardError
            nil
          end
          rows.compact!
          rows.select! { |r| want_ok == true ? r[:success] == true : r[:success] == want_ok } unless want_ok.nil?
          rows.select! { |r| Array(r[:tags]).any? { |t| t.to_s.downcase.include?(tag) } } unless tag.empty?
          rows.reverse.first(limit)
        end

        # Supported Method Parameters::
        # stats = PWN::AI::Agent::Learning.stats

        public_class_method def self.stats
          rows   = outcomes(limit: 10_000)
          total  = rows.length
          ok     = rows.count { |r| r[:success] == true }
          skills = defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) ? PWN::Skills.keys.length : 0
          mem    = defined?(PWN::Memory) ? PWN::Memory.load.keys.length : 0
          raw    = total.positive? ? (ok.to_f / total).round(3) : 0.0
          jmean  = total.positive? ? weighted_judge_mean(rows: rows) : nil
          distrust = 0.0
          distrust = Reward.proxy_distrust.to_f.clamp(0.0, 1.0) if defined?(Reward) && Reward.respond_to?(:proxy_distrust)
          {
            total_outcomes: total,
            successes: ok,
            failures: total - ok,
            success_rate: raw,
            adjusted_success_rate: discount_success_rate(proxy: raw, judge: jmean, distrust: distrust),
            proxy_distrust: distrust,
            skills_known: skills,
            memory_entries: mem,
            judge_mean: jmean,
            reward_sentinel: (Reward.sentinel if defined?(Reward)),
            calibration: (Metrics.calibration if defined?(Metrics) && Metrics.respond_to?(:calibration)),
            preference_pairs: (Reward.preferences(limit: 100_000).length if defined?(Reward)),
            tool_metrics: (Metrics.summary(limit: 5) if defined?(Metrics)),
            extrospection: (Extrospection.stats if defined?(Extrospection))
          }
        end

        # Supported Method Parameters::
        # ctx = PWN::AI::Agent::Learning.to_context(
        #   limit: 'optional - number of recent outcomes to surface (default 5)'
        # )

        public_class_method def self.to_context(opts = {})
          limit = opts[:limit] || 5
          # Fetch a wider window so prefer_primary_tasks can drop critic/red_team
          # envelope rows (REQUEST:/GOAL: prefixes) without starving the block.
          rows  = prefer_primary_tasks(rows: outcomes(limit: limit * 4)).first(limit)
          fails = prefer_primary_tasks(rows: outcomes(limit: 200, success: false))
          # Do not mirror the same ids under both headings — that doubled the
          # failure signal and made RECENT OUTCOMES == RECENT FAILURES when the
          # last N attempts all failed (the injected block looked "stuck").
          row_ids = rows.map { |r| r[:id] }.compact
          fails = fails.reject { |r| row_ids.include?(r[:id]) }.first(limit)
          return '' if rows.empty? && fails.empty?

          fmt = lambda do |r|
            flag = case r[:success]
                   when true then '✓'
                   when 'soft', :soft then '∼'
                   else '✗'
                   end
            score = r.key?(:score) ? format('%.2f', r[:score].to_f) : '-'
            task  = display_task(task: r[:task])
            line  = "  #{flag} [#{score}] #{task} (#{r[:timestamp]})"
            # Surface a one-line cause crumb so the agent can actually learn
            # from failures instead of only seeing that they failed.
            if r[:success] != true
              crumb = cause_crumb(details: r[:details])
              line += "\n      cause: #{crumb}" unless crumb.empty?
            end
            line
          end
          s   = stats
          jm  = s[:judge_mean]
          d   = s[:proxy_distrust].to_f
          rate = d > 0.05 ? s[:adjusted_success_rate] : s[:success_rate]
          tag  = d > 0.05 ? ' adj' : ''
          hdr = "RECENT OUTCOMES (success_rate=#{(rate.to_f * 100).round(1)}%#{tag}#{" judge_mean=#{jm}" if jm} over #{s[:total_outcomes]} attempts)"
          out = "#{hdr}\n#{rows.map(&fmt).join("\n")}\n"
          out += "RECENT FAILURES (learn from these — do not repeat)\n#{fails.map(&fmt).join("\n")}\n" unless fails.empty?
          "#{out}\n"
        end

        # Supported Method Parameters::
        # msgs = PWN::AI::Agent::Learning.exemplars_for(
        #   request: 'required - current user request',
        #   limit: 'optional - max exemplar traces to return (default 1)',
        #   max_msgs: 'optional - cap on messages per exemplar (default 6)'
        # )
        #
        # Retrieval-augmented BEHAVIOUR: keyword-matches request against
        # prior successful outcomes in learning.jsonl, loads the matching
        # session, and compresses its (user, tool, assistant) trace into a
        # short few-shot exemplar Loop.run splices between system and user.
        # Local models are dramatically better with 1 concrete example than
        # with 25 abstract lessons.

        public_class_method def self.exemplars_for(opts = {})
          request  = opts[:request].to_s.downcase
          limit    = (opts[:limit]    || 1).to_i
          max_msgs = (opts[:max_msgs] || 6).to_i
          return [] if request.strip.empty?

          tokens = request.scan(/[a-z0-9_]{3,}/).uniq
          return [] if tokens.empty?

          now = Time.now.utc
          # C2 — prioritized replay: priority = judge_score × recency_decay × keyword_sim
          # C2 — strict success:true only (excludes HER success:'soft'). Also
          # down-weight any residual hindsight-tagged rows so partial failures
          # never launder into full-strength few-shot exemplars.
          # P20 — strict success:true AND prefer high judge scores. Drop rows
          # with explicit low ORM score so proxy-true / judge-low cannot be few-shot.
          pool = outcomes(limit: 500, success: true).reject { |r| r[:session_id].to_s.empty? }
          pool = pool.reject { |r| r.key?(:score) && r[:score].to_f < 0.6 }
          scored = pool.map do |r|
            sim   = tokens.count { |t| r[:task].to_s.downcase.include?(t) }.to_f / tokens.length
            age_d = (now - Time.parse(r[:timestamp].to_s)) / 86_400.0
            decay = Math.exp(-age_d / 30.0)
            score = (r[:score] || 1.0).to_f
            tags  = Array(r[:tags]).map(&:to_s)
            # HER / soft / hindsight → 0.35× so they cannot dominate C2 priority
            score *= 0.35 if r[:success].to_s == 'soft' || tags.intersect?(%w[hindsight her soft])
            [r, sim * decay * score]
          rescue StandardError
            [r, 0.0]
          end
          hits = scored.reject { |_, pr| pr <= 0.0 }.sort_by { |_, pr| -pr }.first(limit).map(&:first)

          hits.flat_map { |r| compress_exemplar(session_id: r[:session_id], max_msgs: max_msgs) }
        rescue StandardError
          []
        end

        # Supported Method Parameters::
        # info = PWN::AI::Agent::Learning.export_finetune(
        #   format: 'optional - :sharegpt (default) | :openai_jsonl',
        #   out: 'optional - output path (default ~/.pwn/finetune/pwn-YYYYMMDD.jsonl)',
        #   min_tools: 'optional - only sessions with >= N tool messages (default 1)'
        # )
        #
        # Turns the learning corpus into a supervised dataset: every session
        # whose learning.jsonl outcome is success:true becomes one training
        # sample (system, user, assistant/tool_calls, tool, ..., final). Pair
        # with a weekly PWN::Cron job that runs `ollama create <tag>-pwn -f
        # Modelfile` over the export - the only path to ACTUAL parity with a
        # frontier model, because it changes the weights not just the scaffold.

        # P12 — SFT quality gate (as hard as DPO source-cap): drop HER/soft,
        # low judge_score, auto-only noise without score, and PRM-compress
        # trajectories so LoRA is not 5MB of "how we flailed".
        SFT_MIN_SCORE = 0.6
        SFT_MAX_TOOL_CHARS = 1_200

        public_class_method def self.export_finetune(opts = {})
          fmt       = (opts[:format] || :sharegpt).to_sym
          min_tools = (opts[:min_tools] || 1).to_i
          min_score = (opts[:min_score] || SFT_MIN_SCORE).to_f
          compress  = opts.key?(:compress) ? opts[:compress] : true
          FileUtils.mkdir_p(FINETUNE_DIR)
          out = opts[:out] || File.join(FINETUNE_DIR, "pwn-#{Time.now.utc.strftime('%Y%m%d')}.jsonl")

          # 4.1 / P12 — exclude HER soft-success + low-score + untagged auto flail
          gold = outcomes(limit: 10_000, success: true).reject do |r|
            tags = Array(r[:tags]).map(&:to_s)
            soft = r[:success].to_s == 'soft' || tags.intersect?(%w[hindsight her soft])
            low  = !r[:score].nil? && r[:score].to_f < min_score
            # require a score when present in corpus era that has scores
            soft || low
          end
          # prefer highest-score outcome per session
          by_sid = {}
          gold.each do |r|
            sid = r[:session_id].to_s
            next if sid.empty?

            prev = by_sid[sid]
            by_sid[sid] = r if prev.nil? || r[:score].to_f >= prev[:score].to_f
          end
          sids = by_sid.keys
          rows = 0
          dropped = { tools: 0, empty: 0, load: 0 }
          File.open(out, 'w') do |f|
            sids.each do |sid|
              t = begin
                PWN::Sessions.load(session_id: sid)
              rescue StandardError
                dropped[:load] += 1
                next
              end
              tool_n = t.count { |e| e[:role].to_s == 'tool' }
              if tool_n < min_tools
                dropped[:tools] += 1
                next
              end

              conv = if compress
                       compress_finetune_trace(transcript: t, max_tool_chars: SFT_MAX_TOOL_CHARS)
                     else
                       t.map { |e| { role: e[:role].to_s, content: e[:content].to_s } }
                        .reject { |e| e[:role] == 'system' && e[:content].start_with?('Session started') }
                     end
              if conv.nil? || conv.empty? || conv.none? { |m| m[:role].to_s == 'assistant' }
                dropped[:empty] += 1
                next
              end

              line = case fmt
                     when :openai_jsonl then { messages: conv }
                     else { conversations: conv.map { |m| { from: sharegpt_role(role: m[:role]), value: m[:content] } } }
                     end
              f.puts(JSON.generate(line))
              rows += 1
            end
          end
          {
            path: out, format: fmt, sessions: sids.length, samples: rows,
            bytes: File.size(out), min_score: min_score, compressed: compress,
            dropped: dropped
          }
        end

        # Supported Method Parameters::
        # skill = PWN::AI::Agent::Learning.distill_skill(
        #   name: 'required - snake_case name for the new skill',
        #   session_id: 'optional - PWN::Sessions id to mine (uses its transcript)',
        #   content: 'optional - explicit markdown body; overrides transcript mining',
        #   references: 'optional - Array of reference URLs / CWE / CVE / ATT&CK ids'
        # )

        public_class_method def self.distill_skill(opts = {})
          raise 'ERROR: name is required' if opts[:name].to_s.strip.empty?

          body = opts[:content].to_s
          body = build_skill_from_session(session_id: opts[:session_id], name: opts[:name]) if body.strip.empty? && opts[:session_id]
          raise 'ERROR: content or session_id is required' if body.strip.empty?

          root = skills_dir
          out  = PWN::Config.write_skill(
            name: opts[:name],
            description: opts[:description],
            content: body,
            references: opts[:references],
            pwn_skills_path: root
          )
          PWN::Config.load_skills(pwn_skills_path: root) if PWN::Config.respond_to?(:load_skills)
          note_outcome(task: "distill_skill:#{out[:name]}", success: true, details: "Saved #{out[:path]}", tags: %w[skill auto])
          out.merge(saved: true)
        end

        # Fold RL artefacts (mistakes / structured_fix / an explicit lesson)
        # into an existing skill. Does not create skills (use distill_skill /
        # skill_create). Does not write loop-law. Dedupes by mistake signature.
        public_class_method def self.update_skill(opts = {})
          dry = opts[:dry_run] ? true : false
          lesson = opts[:lesson].to_s.strip
          notes = rl_skill_notes(
            signature: opts[:signature],
            request: opts[:request] || opts[:query],
            lesson: lesson
          )
          return { updated: false, reason: 'no rl notes' } if notes.empty?

          target = locate_skill_for_update(
            name: opts[:name],
            query: opts[:query] || opts[:request] || notes.map { |n| n[:text] }.join(' ')
          )
          return { updated: false, reason: 'no matching skill', notes: notes } unless target

          body = skill_body_without_frontmatter(meta: target[:meta])
          added = []
          notes.each do |note|
            next if body.include?(note[:id])

            added << note
          end
          return { updated: false, name: target[:name], reason: 'already folded', notes: notes } if added.empty?

          block = added.map { |n| "- [#{n[:id]}] #{n[:text]}" }.join("\n")
          body = if body.match?(/^\#{1,3}\s*RL feedback\s*$/i)
                   "#{body.rstrip}\n#{block}\n"
                 else
                   "#{body.rstrip}\n\n## RL feedback\n#{block}\n"
                 end
          return { updated: false, dry_run: true, name: target[:name], added: added.map { |n| n[:text] } } if dry

          root = skills_dir
          out = PWN::Config.write_skill(
            name: target[:name],
            description: target[:meta][:description],
            content: body,
            references: target[:meta][:references],
            license: (target[:meta][:frontmatter] || {})['license'],
            allowed_tools: target[:meta][:allowed_tools],
            metadata: (target[:meta][:frontmatter] || {})['metadata'],
            pwn_skills_path: root
          )
          PWN::Config.load_skills(pwn_skills_path: root) if PWN::Config.respond_to?(:load_skills)
          note_outcome(
            task: "skills_update:#{target[:name]}",
            success: true,
            details: "Folded #{added.length} RL note(s)",
            tags: %w[skill rl]
          )
          out.merge(updated: true, added: added.map { |n| n[:id] })
        rescue StandardError => e
          { updated: false, error: "#{e.class}: #{e.message}" }
        end

        # Supported Method Parameters::
        # report = PWN::AI::Agent::Learning.reflect(
        #   session_id: 'required - PWN::Sessions id to analyse',
        #   dry_run: 'optional - when true, do not write to Memory/Skills (default false)'
        # )
        #
        # Uses PWN::AI::Agent::Reflect (when available) to LLM-summarise the
        # session into structured lessons. Falls back to a heuristic
        # extractor when module_reflection is disabled so learning never stops.

        public_class_method def self.reflect(opts = {})
          session_id = opts[:session_id]
          dry_run    = opts[:dry_run] ? true : false
          raise 'ERROR: session_id is required' if session_id.to_s.empty?

          transcript = PWN::Sessions.load(session_id: session_id)
          return { session_id: session_id, lessons: [], reason: 'empty transcript' } if transcript.empty?

          lessons = introspective_lessons(transcript: transcript)
          source, conf = lessons.empty? ? [:heuristic, 0.3] : [:reflect, 0.8]
          lessons = heuristic_lessons(transcript: transcript) if lessons.empty?

          saved = []
          lessons.each do |l|
            next if l.to_s.strip.empty?

            key = :"reflect_#{session_id}_#{Digest::SHA256.hexdigest(l)[0, 8]}"
            # M3 — provenance + confidence + ttl so consolidate evicts
            # low-confidence heuristic lessons before hand-written ones.
            PWN::Memory.remember(key: key, value: l, category: :lesson, source: source, confidence: conf, importance: conf, ttl: source == :heuristic ? 7 * 86_400 : nil) unless dry_run
            saved << { key: key, lesson: l }
          end
          consolidate unless dry_run

          { session_id: session_id, lessons: saved, count: saved.length, dry_run: dry_run }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Learning.auto_introspect(
        #   session_id: 'required - id of the just-completed session',
        #   request: 'optional - original user request (for outcome logging)',
        #   final: 'optional - final assistant answer (for outcome logging)'
        # )
        #
        # Called by Loop.run when PWN::Env[:ai][:agent][:auto_introspect] is
        # truthy. Never raises — learning must not break the primary loop.

        public_class_method def self.auto_introspect(opts = {})
          session_id = opts[:session_id]
          return unless session_id
          return unless auto_introspect_enabled?

          # Hermes split: Loop.run is on the stack → defer critic/judge/PRM/HER
          # onto a daemon thread so the user already has the reply. Specs,
          # cron, and tools pass through (inline:true or no user-path depth).
          return TurnFinalizer.defer(opts.merge(inline: true)) if defined?(TurnFinalizer) && !opts[:inline] && TurnFinalizer.should_defer?

          t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          stages_run = []
          stages_skipped = []
          budget_hot = begin
            defined?(Loop) && Loop.respond_to?(:budget_exhaustion_hot?, true) &&
              Loop.send(:budget_exhaustion_hot?)
          rescue StandardError
            false
          end

          elapsed_ms = lambda do
            ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - t0) * 1000).round
          end
          # soft = skip expensive; hard = stop almost everything
          over_soft = lambda do
            ms = elapsed_ms.call
            ms >= INTROSPECT_SOFT_MS || budget_hot
          end
          over_hard = lambda do
            ms = elapsed_ms.call
            ms >= INTROSPECT_HARD_MS
          end

          proxy_ok = infer_success(session_id: session_id, final: opts[:final])

          crit = { verdict: :pass, source: :skipped }
          # Live-turn critic is always text-only. A tool-armed persona is
          # another Loop.run of the same goal (opens more browsers, never
          # returns the operator answer). Cron/practice still call
          # Curriculum.critic without text_only.
          if !defined?(Curriculum) || over_hard.call
            stages_skipped << :critic
          else
            stages_run << :critic_text_only
            crit = Curriculum.critic(
              request: opts[:request],
              final: opts[:final],
              session_id: session_id,
              text_only: true
            )
          end

          # R1 judge — always attempt (heuristic is cheap; LLM gated inside)
          stages_run << :judge
          v = Reward.judge(request: opts[:request], final: opts[:final], session_id: session_id, proxy_ok: proxy_ok, predicted: opts[:predicted]) if defined?(Reward)
          v ||= { score: proxy_ok ? 1.0 : 0.0, success: proxy_ok, verdict: proxy_ok ? :solved : :wrong }
          v[:score] = [v[:score], 0.3].min if crit[:verdict] == :flaw && v[:score].to_f < 0.6
          # P29 — critic floor used to leave stale verdict=:solved at score=0.3,
          # producing learning.jsonl rows tagged "solved" with success=false
          # (116+ rows). Always resync verdict/success from the final score.
          v[:verdict] = verdict_for_score(score: v[:score])
          v[:success] = v[:score].to_f >= 0.6
          ok = v[:success]

          # W1 pending user_correction pair
          pend = Thread.current[:pwn_pending_pref]
          if pend && ok && defined?(Reward)
            stages_run << :user_correction_pref
            Reward.record_preference(
              prompt: pend[:prompt],
              rejected: pend[:rejected],
              chosen: opts[:final].to_s,
              source: :user_correction,
              shape: :revised_answer,
              force: true
            )
            Thread.current[:pwn_pending_pref] = nil
          end

          # Soft plan-quality feature (W3) — tag only; not full DPO.
          plan_cov = nil
          if defined?(Reward) && Reward.respond_to?(:plan_coverage)
            begin
              plan_for_cov = opts[:plan]
              unless plan_for_cov.nil?
                plan_cov = Reward.plan_coverage(
                  plan: plan_for_cov || [],
                  final: opts[:final],
                  request: opts[:request],
                  session_id: session_id
                )
                stages_run << :plan_coverage if plan_cov && plan_cov[:total].to_i.positive?
              end
            rescue StandardError => e
              warn "[pwn-ai/learning] plan_coverage swallowed: #{e.class}: #{e.message}"
            end
          end

          stages_run << :note_outcome
          outcome_tags = ['auto', 'loop', v[:verdict].to_s]
          outcome_tags << plan_cov[:tag] if plan_cov && plan_cov[:tag]
          outcome_tags << "plan_cover=#{plan_cov[:score]}" if plan_cov && plan_cov[:total].to_i.positive?
          # P29 — persist the bare user ask (strip REQUEST:/GOAL: envelopes at write time)
          task_txt = display_task(task: opts[:request].to_s)
          task_txt = opts[:request].to_s[0, 100] if task_txt.empty?
          note_outcome(
            task: task_txt,
            success: ok,
            score: v[:score],
            details: "#{v[:verdict]}(#{v[:score].to_f.round(2)}) #{v[:rationale]} | #{opts[:final].to_s[0, 200]}",
            session_id: session_id,
            tags: outcome_tags,
            judge_source: v[:source]
          )

          stages_run << :fold_judge
          fold_judge_into_metrics(session_id: session_id, score: v[:score], confidence: v[:confidence])
          # R5 — close the live MDP episode with the ORM terminal reward.
          if defined?(PWN::AI::Agent::Policy) && Policy.respond_to?(:finish)
            stages_run << :policy
            Policy.finish(
              session_id: session_id,
              score: v[:score],
              confidence: v[:confidence],
              verdict: v[:verdict],
              proxy_ok: ok,
              final: opts[:final],
              ts_state: opts[:ts_state]
            )
          end

          # R2 PRM — skip under hard cap (expensive LLM); keep under soft if heuristic path
          if over_hard.call || !defined?(Reward) || v[:score].to_f < 0.6
            stages_skipped << :prm
          else
            stages_run << :prm
            Reward.prm(request: opts[:request], session_id: session_id)
          end

          # C3 HER — only on failure; skip hard
          if !ok && defined?(Curriculum) && !over_hard.call
            stages_run << :hindsight
            Curriculum.hindsight(request: opts[:request], final: opts[:final], session_id: session_id)
          else
            stages_skipped << :hindsight unless ok
          end

          # W3 calibrate — cheap; always write so Metrics.calibration is never empty.
          predicted = opts[:predicted]
          predicted = recover_predicted_from_session(session_id: session_id) if predicted.nil?
          stages_run << :calibrate if defined?(Curriculum)

          # reflect on success — skip soft/hard (LLM + memory writes)
          # M4.1 — also reflect when the request/final is a process SOP
          # (code hygiene) even if judge score < 0.6, so rubocop/rake
          # lessons still land in PWN::Memory.
          process_sop = process_sop_text?(text: "#{opts[:request]} #{opts[:final]}")
          if (ok || process_sop) && !over_soft.call
            stages_run << :reflect
            reflect(session_id: session_id)
          elsif ok || process_sop
            stages_skipped << :reflect
            # Cheap path under soft budget: still promote a canned process lesson
            if process_sop && defined?(PWN::Memory)
              promote_process_lesson(
                entry: {
                  task: opts[:request].to_s[0, 120],
                  success: ok,
                  score: v[:score],
                  details: opts[:final].to_s[0, 500],
                  tags: %w[auto process_sop]
                }
              )
            end
          end

          # R3 sentinel — cheap disk math; always
          if defined?(Reward)
            stages_run << :sentinel
            Reward.sentinel
          end

          # E ambient extrospect — skip soft (can launch probes)
          if defined?(Extrospection) && !over_soft.call
            stages_run << :extrospect
            Extrospection.auto_extrospect(session_id: session_id)
          else
            stages_skipped << :extrospect
          end

          # Keep ~/.pwn RL stores lean on the feedback path (memory +
          # learning.jsonl + mistakes + sessions). Throttled; never raises.
          # Disk-only work: skip only hard budget / budget_hot.
          begin
            if !over_hard.call && !budget_hot && should_gc_stores?
              stages_run << :lean_gc
              gc_stores!(current_session_id: session_id)
            elsif should_gc_stores?
              stages_skipped << :lean_gc
            end
          rescue StandardError => e
            warn "[pwn-ai/learning] post-introspect lean swallowed: #{e.class}: #{e.message}"
          end

          {
            ok: ok,
            score: v[:score],
            elapsed_ms: elapsed_ms.call,
            budget_hot: budget_hot,
            stages_run: stages_run,
            stages_skipped: stages_skipped
          }
        rescue StandardError => e
          warn "[pwn-ai/learning] auto_introspect swallowed: #{e.class}: #{e.message}"
          nil
        end

        public_class_method def self.flip_last_outcome(opts = {})
          return { flipped: false } unless File.exist?(LEARNING_FILE)

          lines = File.readlines(LEARNING_FILE)
          return { flipped: false } if lines.empty?

          last = JSON.parse(lines.last, symbolize_names: true)
          return { flipped: false } if opts[:session_id] && last[:session_id] && last[:session_id] != opts[:session_id]
          return { flipped: false } unless last[:success]

          last[:success]    = false
          last[:flipped_by] = 'user_correction'
          last[:details]    = "#{last[:details]} | CORRECTED: #{opts[:reason].to_s[0, 200]}".strip
          last[:score]      = 0.0
          lines[-1] = "#{JSON.generate(last)}\n"
          File.write(LEARNING_FILE, lines.join)
          if defined?(Reward) && Reward.respond_to?(:record_preference)
            Reward.record_preference(
              prompt: last[:task].to_s,
              rejected: last[:details].to_s,
              chosen: opts[:reason].to_s,
              source: :user_correction
            )
          end
          { flipped: true, id: last[:id], rejected: last[:details].to_s[0, 2_000] }
        rescue StandardError
          { flipped: false }
        end

        # Supported Method Parameters::
        # removed = PWN::AI::Agent::Learning.consolidate(
        #   max_entries: 'optional - hard cap on PWN::Memory size (default MAX_MEMORY_ENTRIES)'
        # )
        #
        # Deduplicates near-identical lesson values and prunes the oldest
        # entries once the cap is exceeded so the injected MEMORY block
        # stays high-signal.

        public_class_method def self.consolidate(opts = {})
          cap = opts[:max_entries] || MAX_MEMORY_ENTRIES
          return { removed: 0 } unless defined?(PWN::Memory)

          mem = nil
          load_err = nil
          begin
            mem = PWN::Memory.load
          rescue StandardError => e
            load_err = e
          end
          if load_err
            warn "[pwn-ai/learning] consolidate aborted (memory load failed): #{load_err.class}: #{load_err.message}"
            return { removed: 0, aborted: true, error: "#{load_err.class}: #{load_err.message}" }
          end
          removed = []

          # M1 — semantic clustering: embed :lesson entries, greedy-merge
          # near-duplicates (cosine ≥ 0.92) via Reflect into ONE imperative
          # lesson. Falls back to sha-dedup when no embed backend.
          removed.concat(semantic_merge(mem: mem)) if defined?(PWN::MemoryIndex) && PWN::MemoryIndex.available?

          seen = {}
          mem.each do |k, v|
            sig = Digest::SHA256.hexdigest(v[:value].to_s.strip.downcase)[0, 16]
            seen[sig] ? removed << k : seen[sig] = k
          end
          removed.uniq.each { |k| mem.delete(k) }

          # M3 — evict by (age/ttl) / (importance × confidence), NOT
          # oldest-first. Hand-written high-value lessons survive; low-
          # confidence :heuristic auto-gen self-evicts first.
          if mem.size > cap
            now = Time.now.utc
            scored = mem.map do |k, v|
              if defined?(PWN::Memory) && PWN::Memory.respond_to?(:protected_entry?) &&
                 PWN::Memory.protected_entry?(key: k, entry: v)
                next [k, Float::INFINITY]
              end

              age_d = (now - Time.parse(v[:timestamp].to_s)) / 86_400.0
              ttl_d = (v[:ttl].to_f / 86_400.0)
              imp   = (v[:importance] || 0.5).to_f.clamp(0.05, 1.0)
              conf  = (v[:confidence] || (v[:source].to_s == 'human' ? 0.95 : 0.5)).to_f.clamp(0.05, 1.0)
              staleness = ttl_d.positive? ? age_d / ttl_d : age_d / 90.0
              # lower score = drop first; Infinity protected sorts last
              [k, -(staleness / (imp * conf))]
            rescue StandardError
              [k, 0.0]
            end
            # sort ascending by score so lowest (most stale/low-imp) first
            ordered = scored.sort_by { |_k, s| s }
            drop = []
            ordered.each do |pair|
              k = pair[0]
              break if mem.size - drop.size <= cap
              next if defined?(PWN::Memory) && PWN::Memory.respond_to?(:protected_entry?) &&
                      PWN::Memory.protected_entry?(key: k, entry: mem[k])

              drop << k
            end
            drop.each { |k| mem.delete(k) }
            removed.concat(drop)
          end
          PWN::Memory.save(mem: mem, force: mem.empty?)
          if PWN::Memory.respond_to?(:lean!)
            begin
              PWN::Memory.lean!
            rescue StandardError => e
              warn "[pwn-ai/learning] post-consolidate memory.lean! swallowed: #{e.class}: #{e.message}"
            end
          end
          { removed: removed.uniq.length, remaining: mem.size }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Learning.reset

        public_class_method def self.reset
          FileUtils.rm_f(LEARNING_FILE)
          { cleared: true }
        end

        # -------------------------------------------------------------
        # privates
        # -------------------------------------------------------------

        # P20 — attribute episode judge score to every tool used in session.
        private_class_method def self.fold_judge_into_metrics(opts = {})
          return unless defined?(Metrics) && Metrics.respond_to?(:record_judge)

          sid = opts[:session_id]
          score = opts[:score]
          conf = opts[:confidence]
          src = opts[:source]
          return if sid.to_s.empty? || score.nil?
          return unless defined?(PWN::Sessions)

          names = PWN::Sessions.load(session_id: sid)
                               .select { |e| e[:role].to_s == 'tool' }
                               .map { |e| e[:content].to_s[/\A([a-z0-9_]+)\s*→/i, 1] }
                               .compact
                               .uniq
          names.each { |n| Metrics.record_judge(name: n, score: score, confidence: conf, source: src) }
        rescue StandardError
          nil
        end

        # P22 — recover plan_first p(success)= from session transcript when
        # the live return floated away (rescue path / degrade).
        private_class_method def self.recover_predicted_from_session(opts = {})
          # Prefer live stash from plan_first in this process.
          stash = Thread.current[:pwn_plan_predicted]
          return stash.to_f.clamp(0.0, 1.0) unless stash.nil?

          sid = opts[:session_id]
          return nil if sid.to_s.empty? || !defined?(PWN::Sessions)

          entries = PWN::Sessions.load(session_id: sid)
          plan = entries.reverse.find do |e|
            e[:role].to_s == 'assistant' && e[:content].to_s.match?(/\bPLAN:\b|p\(success\)\s*=/i)
          end
          return nil unless plan

          plan[:content].to_s[/p\(success\)\s*=\s*([01](?:\.\d+)?)/i, 1]&.to_f
        rescue StandardError
          nil
        end

        # M4.1 — keyword gate for "process / hygiene" SOPs the operator keeps
        # re-requesting (rubocop, rake, rspec, conventions). These must become
        # durable Memory lessons, not just learning.jsonl rows.
        PROCESS_SOP_RX = %r{\b(rubocop|rake\b|rspec|bundle\s+exec|conventions?|lint(?:ing)?|style/|code\s*hygiene|post[- ]?patch|after\s+(?:every\s+)?(?:patch|change|edit))\b}i

        private_class_method def self.process_sop_text?(opts = {})
          opts[:text].to_s.match?(PROCESS_SOP_RX)
        rescue StandardError
          false
        end

        # Promote a short, imperative process lesson into PWN::Memory when the
        # outcome looks like a repeated hygiene SOP. Idempotent per key.
        private_class_method def self.promote_process_lesson(opts = {})
          entry = opts[:entry] || {}
          blob  = "#{entry[:task]} #{entry[:details]} #{Array(entry[:tags]).join(' ')}"
          return nil unless process_sop_text?(text: blob)

          # Only promote successes or near-successes / operator-driven asks
          score = entry[:score]
          okish = entry[:success] == true || entry[:success] == 'soft' ||
                  (score && score.to_f >= 0.5) ||
                  process_sop_text?(text: entry[:task].to_s)
          return nil unless okish

          lesson =
            if blob.match?(/rubocop/i) && blob.match?(/rake|rspec/i)
              'After every code change under /opt/pwn: run `bundle exec rubocop -a` on touched files, then `bundle exec rake` (or targeted rspec). Fix offenses and failures before claiming done. Do not wait for the operator to re-ask.'
            elsif blob.match?(/rubocop/i)
              'After every Ruby edit: run `bundle exec rubocop -a` on the touched paths and clear all offenses before the final answer.'
            elsif blob.match?(/rake|rspec/i)
              'After every code change: run the relevant `bundle exec rspec` / `bundle exec rake` target and leave the suite green before the final answer.'
            else
              'After code changes: run project lint + tests (rubocop, rake/rspec) and fix violations before declaring the task complete.'
            end

          key = :process_sop_code_hygiene
          # Reinforce importance if already present; never duplicate noisy keys
          existing = PWN::Memory.load[key]
          conf = [((existing && existing[:confidence]) || 0.6).to_f + 0.05, 0.99].min
          PWN::Memory.remember(
            key: key,
            value: lesson,
            category: :lesson,
            source: :process_sop,
            confidence: conf,
            importance: 0.95,
            ttl: nil
          )
          { key: key, lesson: lesson, confidence: conf }
        rescue StandardError => e
          warn "[pwn-ai/learning] promote_process_lesson swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Weighted mean of stored outcome scores. LLM ORM rows outweigh
        # heuristic-overlap rows so the LIVE haircut is an outcome signal.
        private_class_method def self.weighted_judge_mean(opts = {})
          rows = Array(opts[:rows])
          return nil if rows.empty?

          have_src = rows.any? { |r| !r[:judge_source].to_s.empty? }
          if have_src && defined?(Reward) && Reward.respond_to?(:judge_sample_weight)
            num = 0.0
            den = 0.0
            rows.each do |r|
              score = r[:score] ? r[:score].to_f : { true => 1.0, false => 0.0 }[r[:success]]
              next if score.nil?

              wt = Reward.judge_sample_weight(source: r[:judge_source]).to_f
              num += score * wt
              den += wt
            end
            return den.positive? ? (num / den).round(3) : nil
          end

          jsum = rows.sum { |r| r[:score] ? r[:score].to_f : { true => 1.0, false => 0.0 }[r[:success]] }
          (jsum / rows.length).round(3)
        rescue StandardError
          nil
        end

        # When R3 proxy_distrust or the judge–proxy gap is high, do not treat
        # boolean win-rate as the live reward. Blend toward judge_mean (or
        # shrink toward 0.5 when no judge samples exist).
        private_class_method def self.discount_success_rate(opts = {})
          proxy = opts[:proxy].to_f
          distrust = opts[:distrust].to_f.clamp(0.0, 1.0)
          return proxy.round(3) if distrust <= 0.05

          judge = opts[:judge]
          blended = if judge.nil?
                      proxy - ((proxy - 0.5) * distrust)
                    else
                      (proxy * (1.0 - distrust)) + (judge.to_f * distrust)
                    end
          blended.clamp(0.0, 1.0).round(3)
        end

        # P29 — map score → verdict with the same thresholds as Reward.judge.
        private_class_method def self.verdict_for_score(opts = {})
          s = opts[:score].to_f
          return :solved if s >= 0.6
          return :partial if s >= 0.3

          :wrong
        end

        # Strip critic/red_team envelope prefixes so the injected block shows
        # the human ask, not "REQUEST:\n…\nANSWER:" / "GOAL:\n…\nPLAN:".
        private_class_method def self.display_task(opts = {})
          t = opts[:task].to_s.gsub(/\s+/, ' ').strip
          if t.match?(/\AREQUEST:\s*/i)
            body = t.sub(/\AREQUEST:\s*/i, '')
            body = body.split(/\bANSWER:\s*/i, 2).first.to_s
            t = body.strip
          elsif t.match?(/\AGOAL:\s*/i)
            body = t.sub(/\AGOAL:\s*/i, '')
            body = body.split(/\bPLAN:\s*/i, 2).first.to_s
            t = body.strip
          end
          t[0, 100]
        end

        # Prefer bare user goals over REQUEST:/GOAL: swarm envelopes when both
        # describe the same underlying attempt (offline_judge + critic sessions).
        private_class_method def self.prefer_primary_tasks(opts = {})
          rows = Array(opts[:rows])
          return rows if rows.empty?

          scored = rows.map do |r|
            t = r[:task].to_s
            envelope = t.match?(/\A\s*(REQUEST:|GOAL:)/i) ? 1 : 0
            # Higher is better: bare task first, then newer (rows already newest-first)
            [r, -envelope]
          end
          # stable: keep relative order within same envelope rank
          scored.sort_by.with_index { |(_, rank), i| [rank, i] }.map(&:first)
        end

        private_class_method def self.cause_crumb(opts = {})
          d = opts[:details].to_s.gsub(/\s+/, ' ').strip
          return '' if d.empty?

          # Prefer explicit FLAW / CORRECTED crumbs; else verdict(score) head.
          if (m = d.match(/\bFLAW:\s*(.+)\z/i)) || (m = d.match(/\bFLAW:\s*([^|]+)/i))
            return m[1].to_s.strip[0, 120]
          end
          if (m = d.match(/\bCORRECTED:\s*(.+)\z/i))
            return "corrected: #{m[1].to_s.strip[0, 100]}"
          end

          d[0, 120]
        end

        # One-shot / on-load repair: rewrite tags+details where verdict label
        # disagrees with score (solved @ 0.3 etc.). Safe to call repeatedly.
        public_class_method def self.reconcile_verdict_tags!(opts = {})
          return { repaired: 0 } unless File.exist?(LEARNING_FILE)

          dry = opts[:dry_run] ? true : false
          repaired = 0
          lines = File.readlines(LEARNING_FILE)
          out = lines.map do |l|
            r = JSON.parse(l, symbolize_names: true)
            score = r.key?(:score) ? r[:score].to_f : nil
            next l if score.nil?

            want = verdict_for_score(score: score).to_s
            tags = Array(r[:tags]).map(&:to_s)
            stale = tags & %w[solved partial wrong unknown]
            next l if stale.empty? || stale.include?(want)

            repaired += 1
            next l if dry

            cleaned = tags - %w[solved partial wrong unknown]
            cleaned << want
            r[:tags] = cleaned
            # Fix leading "solved(0.3)" style details head when present
            det = r[:details].to_s
            r[:details] = det.sub(
              /\A(solved|partial|wrong|unknown)\(\d+(?:\.\d+)?\)/i,
              "#{want}(#{format('%.2f', score)})"
            )
            r[:success] = (score >= 0.6) if [true, false].include?(r[:success])
            "#{JSON.generate(r)}\n"
          rescue StandardError
            l
          end
          File.write(LEARNING_FILE, out.join) if !dry && repaired.positive?
          { repaired: repaired, dry_run: dry }
        rescue StandardError => e
          { repaired: 0, error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.auto_introspect_enabled?
          return false unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          PWN::Env.dig(:ai, :agent, :auto_introspect) ? true : false
        rescue StandardError
          false
        end

        FAILURE_FINAL_RX = /\[pwn-ai\] (iteration budget exhausted|engine returned no message)|\b(i (was )?unable to|i could not|i couldn'?t|cannot proceed|failed to)\b/i

        # Derive a success signal stronger than "final answer non-empty":
        # look at the tool-failure ratio inside the just-completed turn AND
        # scan the final text for self-reported failure language. Without
        # this, auto_introspect logs ~100 % success and the negative-feedback
        # side of the learning loop never fires.
        private_class_method def self.infer_success(opts = {})
          final = opts[:final].to_s
          return false if final.strip.empty?
          return false if final.match?(FAILURE_FINAL_RX)

          sid = opts[:session_id]
          return true unless sid && defined?(PWN::Sessions)

          entries = PWN::Sessions.load(session_id: sid).last(200)
          tool    = entries.select { |e| e[:role].to_s == 'tool' }
          return true if tool.empty?

          bad = tool.count do |e|
            c = e[:content].to_s
            defined?(Reward) ? !Reward.semantic_ok(name: c[/^(\w+) →/, 1] || 'shell', raw: c)[:semantic_ok] : c.include?('"success":false')
          end
          (bad.to_f / tool.length) < 0.5
        rescue StandardError
          !final.strip.empty?
        end

        private_class_method def self.rl_skill_notes(opts = {})
          notes = []
          day = Time.now.utc.strftime('%Y-%m-%d')
          lesson = opts[:lesson].to_s.strip
          notes << { id: "lesson:#{Digest::SHA256.hexdigest(lesson)[0, 8]}", text: "[#{day}] #{lesson[0, 400]}" } unless lesson.empty?
          return notes unless defined?(Mistakes)

          rows = []
          if opts[:signature].to_s.strip.empty?
            rows = Mistakes.top(limit: 8, unresolved_only: false)
          else
            hit = Mistakes.find(signature: opts[:signature].to_s)
            rows = hit ? [hit] : []
          end
          req = opts[:request].to_s.downcase
          rows.each do |mistake|
            next unless mistake.is_a?(Hash)

            err = mistake[:error].to_s.downcase
            next if (err.include?('budget') || err.include?('iteration')) && !req.match?(/budget|iterat|exhaust/)

            fix = mistake[:fix].to_s
            sf = mistake[:structured_fix]
            trace = sf.is_a?(Hash) ? sf[:winning_trace].to_s : ''
            next if fix.empty? && trace.empty?

            sig = mistake[:signature].to_s
            next if sig.empty?

            bit = "[#{day}] [#{sig}] #{mistake[:tool]}: #{mistake[:error].to_s[0, 120]}"
            bit = "#{bit} — FIX: #{fix[0, 160]}" unless fix.empty?
            bit = "#{bit} trace: #{trace[0, 160]}" unless trace.empty?
            notes << { id: sig, text: bit }
          end
          notes.uniq { |n| n[:id] }.first(6)
        rescue StandardError
          notes
        end

        private_class_method def self.locate_skill_for_update(opts = {})
          return nil unless defined?(PWN::Skills) && PWN::Skills.is_a?(Hash)

          if opts[:name].to_s.strip.empty?
            query = opts[:query].to_s.downcase
            tokens = query.scan(/[a-z0-9_-]{3,}/).uniq
            return nil if tokens.empty?

            scored = PWN::Skills.map do |name, meta|
              next unless meta.is_a?(Hash)

              hay = "#{name} #{meta[:description]} #{meta[:content]}".downcase
              score = tokens.count { |tok| hay.include?(tok) }
              [name.to_s, meta, score]
            end.compact
            best = scored.max_by { |_, _, score| score }
            return nil unless best && best[2] >= 2

            return { name: best[0], meta: best[1] }
          end

          key = opts[:name].to_s
          meta = PWN::Skills[key.to_sym] || PWN::Skills[key]
          if meta.nil? && defined?(PWN::Config)
            meta = PWN::Skills[PWN::Config.sanitize_skill_name(name: key).to_sym]
            key = PWN::Config.sanitize_skill_name(name: key) if meta
          end
          return nil unless meta.is_a?(Hash)

          { name: key.to_s, meta: meta }
        rescue StandardError
          nil
        end

        private_class_method def self.skill_body_without_frontmatter(opts = {})
          meta = opts[:meta] || {}
          raw = meta[:content].to_s
          return raw unless defined?(PWN::Config) && PWN::Config.respond_to?(:parse_skill_frontmatter)

          parsed = PWN::Config.parse_skill_frontmatter(content: raw)
          body = parsed[:body].to_s
          body.empty? ? raw : body
        rescue StandardError
          opts.dig(:meta, :content).to_s
        end

        private_class_method def self.skills_dir
          if defined?(PWN::Config) && PWN::Config.respond_to?(:pwn_skills_path)
            PWN::Config.pwn_skills_path
          else
            File.join(Dir.home, '.pwn', 'skills')
          end
        rescue StandardError
          File.join(Dir.home, '.pwn', 'skills')
        end

        private_class_method def self.transcript_text(opts = {})
          transcript = opts[:transcript] || []
          transcript.map do |e|
            "[#{e[:role]}] #{e[:content].to_s.gsub(/\s+/, ' ')[0, 400]}"
          end.join("\n")
        end

        private_class_method def self.introspective_lessons(opts = {})
          transcript = opts[:transcript] || []
          return [] unless defined?(PWN::AI::Agent::Reflect)
          return [] unless defined?(PWN::Env) && PWN::Env.is_a?(Hash) && PWN::Env.dig(:ai, :module_reflection)

          req = "Analyse this pwn-ai session transcript and emit up to 5 durable, generalizable lessons (one per line, no numbering, imperative voice) that would make future runs faster or more reliable. Focus on tool selection, error recovery, and target-agnostic technique. Ignore trivia.\n\nTRANSCRIPT:\n#{transcript_text(transcript: transcript)}"
          resp = PWN::AI::Agent::Reflect.on(request: req, suppress_pii_warning: true)
          resp.to_s.lines.map(&:strip).reject(&:empty?).first(5)
        rescue StandardError
          []
        end

        private_class_method def self.heuristic_lessons(opts = {})
          transcript = opts[:transcript] || []
          lessons = []
          transcript.each do |e|
            c = e[:content].to_s
            next unless e[:role].to_s == 'tool'

            # R4 — only true dispatch failures (semantic_ok=false), NOT any
            # stdout containing the substring 'error'. This alone eliminated
            # 64/200 garbage lessons on the reference host.
            tool = c[/^(\w+) →/, 1] || 'tool'
            sem  = defined?(Reward) ? Reward.semantic_ok(name: tool, raw: c) : { semantic_ok: !c.include?('"success":false') }
            next if sem[:semantic_ok]

            err = sem[:err] || c[/"error":"([^"]{5,200})"/, 1] || c[0, 120]
            lessons << "When #{tool} fails with '#{err.to_s.gsub(/\s+/, ' ')[0, 120]}', try a different approach — do not retry verbatim."
          end
          if lessons.empty?
            asst = transcript.rfind { |e| e[:role].to_s == 'assistant' }
            lessons << "Approach that worked: #{asst[:content].to_s.strip[0, 200]}" if asst && !asst[:content].to_s.strip.empty?
          end
          lessons.uniq.first(5)
        end

        # P26 — is this CLAIM_RX hit worth spending a headless browser on?
        # Reject metric crumbs, OS/runtime banner lines, and bare versions.
        private_class_method def self.checkable_claim?(opts = {})
          c = opts[:claim].to_s.strip
          return false if c.empty? || c.length < 8
          return true if c.match?(/CVE-\d{4}-\d{4,7}/i)

          head = c[/\A[A-Za-z][\w.+-]*/].to_s
          return false if CLAIM_METRIC_WORDS.any? { |w| head.casecmp?(w) }
          # require full semver x.y.z for non-CVE claims
          return false unless c.match?(/\bv?\d+\.\d+\.\d+/)

          true
        rescue StandardError
          false
        end

        # Auto fact-check post-filter: local models hallucinate CVEs /
        # versions ~5-10x more than frontier ones. When the active engine is
        # :ollama, scan the final for CVE / version-shaped claims and hand
        # each to Extrospection.verify - refuted claims become
        # Mistakes(tool:'assumption') so KNOWN MISTAKES warns every future
        # run off that specific hallucination.
        private_class_method def self.fact_check_local_final(opts = {})
          eng = defined?(PWN::Env) ? PWN::Env.dig(:ai, :active).to_s.downcase.to_sym : nil
          return unless %i[ollama openwebui].include?(eng)
          return unless defined?(Extrospection) && Extrospection.respond_to?(:verify)

          claims = opts[:final].to_s.scan(CLAIM_RX).flatten.compact.uniq
          claims = claims.select { |c| checkable_claim?(claim: c) }.first(3)
          claims.each { |c| Extrospection.verify(claim: c, commit: true) }
        rescue StandardError => e
          warn "[pwn-ai/learning] fact_check swallowed: #{e.class}: #{e.message}"
        end

        # P12 — PRM-aware SFT trace: keep user + reward>0 tools (else first N) +
        # final assistant, truncate tool payloads. Drops system noise.
        private_class_method def self.compress_finetune_trace(opts = {})
          t = Array(opts[:transcript])
          cap = (opts[:max_tool_chars] || SFT_MAX_TOOL_CHARS).to_i
          fin_idx = t.rindex { |e| e[:role].to_s == 'assistant' && !e[:content].to_s.strip.empty? }
          return [] if fin_idx.nil?

          user_idx = t[0...fin_idx].rindex { |e| e[:role].to_s == 'user' }
          return [] if user_idx.nil?

          window = t[user_idx..fin_idx]
          tools = window.select { |e| e[:role].to_s == 'tool' }
          rewarded = tools.select { |e| e[:step_reward].to_i.positive? }
          tools = rewarded unless rewarded.empty?
          tools = tools.first(8)

          out = []
          out << { role: 'user', content: t[user_idx][:content].to_s[0, 2_000] }
          tools.each do |e|
            out << { role: 'tool', content: e[:content].to_s[0, cap] }
          end
          out << { role: 'assistant', content: t[fin_idx][:content].to_s[0, 4_000] }
          out
        rescue StandardError
          []
        end

        private_class_method def self.compress_exemplar(opts = {})
          sid = opts[:session_id]
          cap = opts[:max_msgs] || 6
          t = PWN::Sessions.load(session_id: sid)
          return [] if t.nil? || t.empty?

          # Prefer the LAST non-empty assistant as the exemplar final.
          # Blank assistants (common when a prior local-model turn stopped
          # with empty content / eval_count=1) must never be few-shot into
          # the next Ollama turn — Qwen/abliterated builds then echo the
          # empty final and the agent loop returns "" to the user.
          fin_idx = t.rindex { |e| e[:role].to_s == 'assistant' && !e[:content].to_s.strip.empty? }
          return [] if fin_idx.nil?

          fin = t[fin_idx]
          # Pair with the nearest preceding user so multi-turn sessions do
          # not attach an unrelated first-user prompt to a later answer.
          user = t[0...fin_idx].reverse.find { |e| e[:role].to_s == 'user' }
          return [] unless user

          # C4 — minimal sufficient trace: prefer steps PRM tagged reward>0
          # scoped to the window between that user and the final answer.
          user_idx = t[0...fin_idx].rindex { |e| e.equal?(user) || (e[:role].to_s == 'user' && e[:content] == user[:content]) } || 0
          window = t[user_idx..fin_idx] || []
          tools = window.select { |e| e[:role].to_s == 'tool' }
          rewarded = tools.select { |e| e[:step_reward].to_i.positive? }
          tools = rewarded unless rewarded.empty?
          tools = tools.first([cap - 2, 0].max)

          # Emit a SINGLE user/assistant pair (never consecutive assistant
          # turns). Many local chat templates (Qwen3, Llama-3) collapse or
          # early-stop when two assistant messages land back-to-back with
          # no user between them — observed as done_reason=stop, eval_count=1,
          # empty content, no tool_calls.
          tool_bits = tools.map { |e| e[:content].to_s[0, 220] }.reject { |s| s.strip.empty? }
          body = +''
          unless tool_bits.empty?
            body << "[exemplar tools]\n"
            tool_bits.each_with_index { |s, i| body << "#{i + 1}. #{s}\n" }
            body << "\n"
          end
          body << "[exemplar final]\n#{fin[:content].to_s.strip[0, 400]}"
          return [] if fin[:content].to_s.strip.empty?

          [
            { role: 'user', content: "[exemplar] #{user[:content].to_s[0, 400]}" },
            { role: 'assistant', content: body }
          ]
        rescue StandardError
          []
        end

        private_class_method def self.sharegpt_role(opts = {})
          case opts[:role].to_s
          when 'user'      then 'human'
          when 'assistant' then 'gpt'
          when 'tool'      then 'observation'
          else 'system'
          end
        end

        private_class_method def self.build_skill_from_session(opts = {})
          session_id = opts[:session_id]
          name       = opts[:name]
          transcript = PWN::Sessions.load(session_id: session_id)
          # C4 — minimal sufficient trace: only steps PRM tagged reward>0
          pool = transcript.select { |e| %w[tool assistant].include?(e[:role].to_s) }
          rewarded = pool.select { |e| e[:step_reward].to_i.positive? }
          pool = rewarded unless rewarded.empty?
          steps = pool.map { |e| "- **#{e[:role]}**: #{e[:content].to_s.strip[0, 300]}" }
          user = transcript.find { |e| e[:role].to_s == 'user' }
          goal = user ? user[:content].to_s.strip[0, 200] : name
          <<~MD
            # #{name.tr('_-', ' ').capitalize}

            _Auto-distilled by PWN::AI::Agent::Learning from session `#{session_id}` on #{Time.now.utc.iso8601}._

            ## Goal
            #{goal}

            ## Observed Procedure
            #{steps.join("\n")}

            ## Notes
            Refine this skill by editing #{name}.md under ~/.pwn/skills.
          MD
        end

        # M1 — greedy cosine clustering over :lesson embeddings, then ask
        # Reflect to merge each cluster into ONE ≤120-char imperative.
        private_class_method def self.semantic_merge(opts = {})
          mem = opts[:mem]
          lessons = mem.select { |_k, v| v[:category].to_s == 'lesson' }
          return [] if lessons.length < 4

          idx = PWN::MemoryIndex.refresh(mem: mem)
          removed = []
          done = {}
          lessons.each_key do |k|
            next if done[k]

            va = idx.dig(k, :vec)
            next unless va

            cluster = lessons.keys.select do |k2|
              next false if k2 == k || done[k2]

              vb = idx.dig(k2, :vec)
              vb && PWN::MemoryIndex.send(:cosine, a: va, b: vb) >= 0.92
            end
            next if cluster.empty?

            group = ([k] + cluster).map { |kk| mem[kk][:value].to_s }
            merged = merge_cluster(values: group)
            mem[k][:value]      = merged
            mem[k][:source]     = 'consolidate'
            mem[k][:confidence] = 0.8
            mem[k][:importance] = [(mem[k][:importance] || 0.5).to_f, 0.7].max
            cluster.each do |kk|
              removed << kk
              done[kk] = true
            end
            done[k] = true
          end
          removed
        rescue StandardError
          []
        end

        private_class_method def self.merge_cluster(opts = {})
          values = opts[:values]
          if defined?(Reflect) && PWN::Env.dig(:ai, :module_reflection)
            req = "Merge these near-duplicate lessons into ONE imperative sentence (≤120 chars, no preamble):\n#{values.map { |v| "- #{v[0, 200]}" }.join("\n")}"
            r = Reflect.on(request: req, suppress_pii_warning: true).to_s.strip.lines.first.to_s.strip
            return r[0, 200] unless r.empty?
          end
          values.min_by(&:length)[0, 200]
        rescue StandardError
          values.first[0, 200]
        end

        # Supported Method Parameters::
        # result = PWN::AI::Agent::Learning.prune_outcomes!(
        #   dry_run: 'optional - Boolean (default false)',
        #   max_rows: 'optional - hard cap (default MAX_OUTCOME_ROWS)',
        #   retain_days: 'optional - age floor for low-value drop',
        #   recent_days: 'optional - always keep newer than this'
        # )
        #
        # Keep gold RL rows (success+score>=0.6+session_id), recent window,
        # high-value tags, and near-miss failures. Dedupe by task+success
        # keeping best score. Truncate details. Never sacrifices exemplar pool.

        public_class_method def self.prune_outcomes!(opts = {})
          dry = opts[:dry_run] ? true : false
          max_rows = (opts[:max_rows] || MAX_OUTCOME_ROWS).to_i
          retain_days = (opts[:retain_days] || OUTCOME_RETAIN_DAYS).to_f
          recent_days = (opts[:recent_days] || OUTCOME_RECENT_DAYS).to_f
          details_max = (opts[:details_max] || OUTCOME_DETAILS_MAX).to_i
          gold_min = (opts[:gold_min_score] || GOLD_MIN_SCORE).to_f

          return { kept: 0, removed: 0, skipped: true } unless File.exist?(LEARNING_FILE)

          before_bytes = File.size(LEARNING_FILE)
          rows = File.readlines(LEARNING_FILE).map do |l|
            JSON.parse(l, symbolize_names: true)
          rescue StandardError
            nil
          end.compact

          now = Time.now.utc
          age_days = lambda do |r|
            (now - Time.parse(r[:timestamp].to_s)) / 86_400.0
          rescue StandardError
            999.0
          end

          protected_row = lambda do |r|
            tags = Array(r[:tags]).map(&:to_s)
            a = age_days.call(r)
            return true if a <= recent_days
            return true if r[:success] == true && r.key?(:score) && r[:score].to_f >= gold_min && r[:session_id].to_s != ''
            return true if r[:success] == true && !r.key?(:score) && r[:session_id].to_s != '' && a <= retain_days
            return true if tags.intersect?(HIGH_VALUE_TAGS)
            return true if r[:success] == false && r.key?(:score) && r[:score].to_f >= 0.5

            false
          end

          rows.reject! { |r| r[:task].to_s.strip.empty? }

          best = {}
          rows.each do |r|
            key = [r[:task].to_s.strip.downcase.gsub(/\s+/, ' ')[0, 160], r[:success].to_s]
            prev = best[key]
            if prev.nil?
              best[key] = r
            else
              ps = prev.key?(:score) ? prev[:score].to_f : -1.0
              rs = r.key?(:score) ? r[:score].to_f : -1.0
              better = rs > ps || (rs == ps && r[:timestamp].to_s > prev[:timestamp].to_s)
              better ||= protected_row.call(r) && !protected_row.call(prev)
              best[key] = r if better
            end
          end
          deduped = best.values
          removed_dupes = rows.size - deduped.size

          truncated = 0
          deduped.each do |r|
            d = r[:details].to_s
            next if d.bytesize <= details_max

            r[:details] = "#{d[0, details_max]}…[compacted]"
            truncated += 1
          end

          protected, unprotected = deduped.partition { |r| protected_row.call(r) }

          kept_unprot = unprotected.reject do |r|
            a = age_days.call(r)
            tags = Array(r[:tags]).map(&:to_s)
            score = r.key?(:score) ? r[:score].to_f : 1.0
            noise_tags = (tags - LOW_VALUE_ONLY_TAGS).empty? && tags.any?
            a > retain_days && noise_tags && score < 0.4
          end

          gold = (protected + kept_unprot).select do |r|
            r[:success] == true && r[:session_id].to_s != '' &&
              (!r.key?(:score) || r[:score].to_f >= gold_min)
          end
          if gold.size < EXEMPLARS_POOL_MIN
            need = EXEMPLARS_POOL_MIN - gold.size
            extra = unprotected.select { |r| r[:success] == true && r[:session_id].to_s != '' }
                               .sort_by { |r| r[:timestamp].to_s }
                               .last(need)
            kept_unprot = (kept_unprot + extra).uniq
          end

          fails = (protected + kept_unprot).reject { |r| r[:success] == true }
          if fails.size < FAILURE_WINDOW_MIN
            need = FAILURE_WINDOW_MIN - fails.size
            extra = unprotected.reject { |r| r[:success] == true }
                               .sort_by { |r| r[:timestamp].to_s }
                               .last(need)
            kept_unprot = (kept_unprot + extra).uniq
          end

          kept = (protected + kept_unprot).uniq
          if kept.size > max_rows
            prot_ids = protected.map { |r| r[:id] }.compact
            over = kept.size - max_rows
            victims = kept.reject { |r| prot_ids.include?(r[:id]) }
                          .sort_by { |r| r[:timestamp].to_s }
                          .first(over)
            v_ids = victims.map { |r| r[:id] }
            kept = kept.reject { |r| v_ids.include?(r[:id]) }
          end

          kept = kept.sort_by { |r| r[:timestamp].to_s }

          atomic_jsonl_write(path: LEARNING_FILE, rows: kept) unless dry

          {
            kept: kept.size,
            removed: (rows.size - kept.size) + removed_dupes,
            deduped: removed_dupes,
            truncated_details: truncated,
            protected: protected.size,
            bytes_before: before_bytes,
            bytes_after: if dry
                           before_bytes
                         else
                           (File.exist?(LEARNING_FILE) ? File.size(LEARNING_FILE) : 0)
                         end,
            dry_run: dry
          }
        end

        # Memory lean + outcome prune.
        public_class_method def self.lean!(opts = {})
          dry = opts[:dry_run] ? true : false
          out = { dry_run: dry }
          out[:memory] = if defined?(PWN::Memory) && PWN::Memory.respond_to?(:lean!)
                           PWN::Memory.lean!(dry_run: dry)
                         else
                           { skipped: true }
                         end
          out[:memory_consolidate] = consolidate(max_entries: opts[:max_entries] || MAX_MEMORY_ENTRIES) unless dry
          out[:learning] = prune_outcomes!(
            dry_run: dry,
            max_rows: opts[:max_rows],
            retain_days: opts[:retain_days],
            recent_days: opts[:recent_days],
            details_max: opts[:details_max],
            gold_min_score: opts[:gold_min_score]
          )
          out
        end

        # One-shot lean across memory + learning + mistakes + sessions.
        # Called from auto_introspect (throttled) so the RL feedback loop
        # keeps ~/.pwn high-signal without a manual learning_gc_stores turn.
        # Supported Method Parameters::
        #   result = PWN::AI::Agent::Learning.gc_stores!(
        #     dry_run: 'optional - Boolean (default false)',
        #     current_session_id: 'optional - never delete this sessions id',
        #     max_entries: 'optional - Memory consolidate cap',
        #     max_rows: 'optional - learning.jsonl cap',
        #     retain_days: 'optional - outcome / session age floor'
        #   )
        public_class_method def self.gc_stores!(opts = {})
          dry = opts[:dry_run] ? true : false
          res = lean!(
            dry_run: dry,
            max_entries: opts[:max_entries],
            max_rows: opts[:max_rows],
            retain_days: opts[:retain_days],
            recent_days: opts[:recent_days],
            details_max: opts[:details_max],
            gold_min_score: opts[:gold_min_score]
          )
          res[:mistakes] = if defined?(Mistakes) && Mistakes.respond_to?(:lean!)
                             Mistakes.lean!(dry_run: dry)
                           else
                             { skipped: true }
                           end
          res[:policy] = if defined?(PWN::AI::Agent::Policy) && Policy.respond_to?(:lean!)
                           Policy.lean!(dry_run: dry)
                         else
                           { skipped: true }
                         end
          res[:sessions] = if defined?(PWN::Sessions) && PWN::Sessions.respond_to?(:lean!)
                             sess_opts = { dry_run: dry }
                             sid = opts[:current_session_id].to_s
                             sess_opts[:current_session_id] = sid unless sid.empty?
                             sess_opts[:retain_days] = opts[:retain_days] if opts.key?(:retain_days)
                             sess_opts[:max_files] = opts[:max_files] if opts.key?(:max_files)
                             PWN::Sessions.lean!(**sess_opts)
                           else
                             { skipped: true }
                           end
          res
        end

        # True every PRUNE_EVERY_N_APPENDS rows, or once learning.jsonl
        # exceeds MAX_OUTCOME_ROWS (forces lean even if modulo miss).
        private_class_method def self.should_gc_stores?
          return true unless File.exist?(LEARNING_FILE)

          lines = File.foreach(LEARNING_FILE).count
          return true if lines >= MAX_OUTCOME_ROWS
          return true if lines.positive? && (lines % PRUNE_EVERY_N_APPENDS).zero?

          false
        rescue StandardError
          false
        end

        private_class_method def self.maybe_prune_outcomes!
          return unless File.exist?(LEARNING_FILE)

          lines = File.foreach(LEARNING_FILE).count
          return if lines < MAX_OUTCOME_ROWS && (lines % PRUNE_EVERY_N_APPENDS != 0)

          prune_outcomes!
        rescue StandardError => e
          warn "[pwn-ai/learning] maybe_prune_outcomes! swallowed: #{e.class}: #{e.message}"
        end

        private_class_method def self.atomic_jsonl_write(opts = {})
          path = opts[:path]
          rows = Array(opts[:rows])
          dir = File.dirname(path)
          FileUtils.mkdir_p(dir)
          bak = "#{path}.bak-lean-#{Time.now.utc.strftime('%Y%m%d')}"
          FileUtils.cp(path, bak) if File.exist?(path) && !File.exist?(bak)
          tmp = File.join(dir, ".#{File.basename(path)}.#{Process.pid}.tmp")
          File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |f|
            f.flock(File::LOCK_EX)
            rows.each { |r| f.puts(JSON.generate(r)) }
            f.flush
            f.fsync
          end
          File.rename(tmp, path)
        ensure
          FileUtils.rm_f(tmp) if defined?(tmp) && tmp && File.exist?(tmp)
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Learning.purge_noise
        #
        # One-shot GC of the pre-R1 garbage: drops every PWN::Memory entry
        # matching the old `SUCCESS: <req> — <final>` / `Avoid repeating
        # failure pattern from <tool>: {"success":true` shapes. Run once
        # after upgrading; subsequent writes never produce these.

        public_class_method def self.purge_noise
          return { removed: 0 } unless defined?(PWN::Memory)

          mem = nil
          load_err = nil
          begin
            mem = PWN::Memory.load
          rescue StandardError => e
            load_err = e
          end
          if load_err
            warn "[pwn-ai/learning] purge_noise aborted (memory load failed): #{load_err.class}: #{load_err.message}"
            return { removed: 0, aborted: true, error: "#{load_err.class}: #{load_err.message}" }
          end
          before = mem.size
          mem.reject! do |_k, v|
            next false unless v[:category].to_s == 'lesson'

            val = v[:value].to_s
            val.start_with?('SUCCESS: ', 'FAILURE: ') ||
              val.match?(/\AAvoid repeating failure pattern from \w+: .{0,5}\{"success":true/)
          end
          PWN::Memory.save(mem: mem, force: mem.empty?)
          { removed: before - mem.size, remaining: mem.size }
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::Learning.note_outcome(task: 'nmap sweep 10.0.0.0/24', success: true, details: '12 hosts up')
              PWN::AI::Agent::Learning.outcomes(limit: 20, success: false)
              PWN::AI::Agent::Learning.reflect(session_id: sid)              # LLM or heuristic → PWN::Memory
              PWN::AI::Agent::Learning.auto_introspect(session_id: sid, request: req, final: text)
              PWN::AI::Agent::Learning.distill_skill(name: 'quick_recon', session_id: sid)
              PWN::AI::Agent::Learning.exemplars_for(request: 'nmap sweep 10/8')  # few-shot for Loop.run
              PWN::AI::Agent::Learning.export_finetune(format: :sharegpt)        # -> ~/.pwn/finetune/*.jsonl
              PWN::AI::Agent::Learning.consolidate(max_entries: 200)         # M1 semantic-merge + M3 importance-evict
              PWN::AI::Agent::Learning.lean!                                 # memory + learning.jsonl prune
              PWN::AI::Agent::Learning.gc_stores!                            # full ~/.pwn RL lean (mem/learn/mistakes/sessions)
              PWN::AI::Agent::Learning.prune_outcomes!                       # learning.jsonl gold-keep cap
              PWN::AI::Agent::Learning.purge_noise                            # one-shot GC of pre-R1 garbage lessons
              PWN::AI::Agent::Learning.to_context(limit: 5)                  # injected by PromptBuilder
              PWN::AI::Agent::Learning.stats
              PWN::AI::Agent::Learning.reset

              Enable end-of-run auto-learning with:
                PWN::Env[:ai][:agent][:auto_introspect] = true
              # auto_introspect throttles gc_stores! every PRUNE_EVERY_N_APPENDS
              # outcomes so ~/.pwn stays lean without a manual GC turn.

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
