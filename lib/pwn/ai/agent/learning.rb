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
      # reusable skills, and prunes / consolidates persistent memory so the
      # agent gets sharper over time instead of accumulating noise.
      #
      # Data flows:
      #   Loop.run --(tool telemetry)--> Metrics.record
      #   Loop.run --(final answer)----> Learning.auto_introspect (opt-in)
      #   model    --(tool calls)------> learning_note_outcome / _distill_skill
      #   PromptBuilder <----------------- Learning.to_context + Metrics.to_context
      #
      # Everything is file-backed under ~/.pwn so it survives across REPL
      # restarts and is shared by every future session.
      module Learning
        LEARNING_FILE      = File.join(Dir.home, '.pwn', 'learning.jsonl')
        FINETUNE_DIR       = File.join(Dir.home, '.pwn', 'finetune')
        MAX_MEMORY_ENTRIES = 200
        CLAIM_RX           = /CVE-\d{4}-\d{4,7}|\b[A-Za-z][\w.+-]{2,}\s+v?\d+\.\d+(?:\.\d+)?\b/

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
          success = opts[:success] ? true : false
          raise 'ERROR: task is required' if task.strip.empty?

          entry = {
            id: Digest::SHA256.hexdigest("#{task}-#{Time.now.to_f}")[0, 12],
            task: task,
            success: success,
            details: opts[:details].to_s[0, 2_000],
            session_id: opts[:session_id],
            tags: Array(opts[:tags]).map(&:to_s),
            timestamp: Time.now.utc.iso8601
          }
          entry[:score] = opts[:score].to_f if opts.key?(:score)
          FileUtils.mkdir_p(File.dirname(LEARNING_FILE))
          File.open(LEARNING_FILE, 'a') { |f| f.puts(JSON.generate(entry)) }

          # M4 — outcomes live in learning.jsonl ONLY. PWN::Memory[:lesson] is
          # reserved for reflect / mistakes_resolve / human — this alone
          # removed 40 % of the noise in the injected MEMORY block.
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
          rows.select! { |r| r[:success] == want_ok } unless want_ok.nil?
          rows.select! { |r| Array(r[:tags]).any? { |t| t.to_s.downcase.include?(tag) } } unless tag.empty?
          rows.reverse.first(limit)
        end

        # Supported Method Parameters::
        # stats = PWN::AI::Agent::Learning.stats

        public_class_method def self.stats
          rows   = outcomes(limit: 10_000)
          total  = rows.length
          ok     = rows.count { |r| r[:success] }
          jsum   = rows.sum { |r| r[:score] ? r[:score].to_f : { true => 1.0, false => 0.0 }[r[:success]] }
          skills = defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) ? PWN::Skills.keys.length : 0
          mem    = defined?(PWN::Memory) ? PWN::Memory.load.keys.length : 0
          {
            total_outcomes: total,
            successes: ok,
            failures: total - ok,
            success_rate: total.positive? ? (ok.to_f / total).round(3) : 0.0,
            skills_known: skills,
            memory_entries: mem,
            judge_mean: total.positive? ? (jsum / total).round(3) : nil,
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
          rows  = outcomes(limit: limit)
          fails = outcomes(limit: 200, success: false).first(limit)
          return '' if rows.empty? && fails.empty?

          fmt = lambda do |r|
            flag = r[:success] ? '✓' : '✗'
            "  #{flag} #{r[:task].to_s[0, 100]} (#{r[:timestamp]})"
          end
          s   = stats
          jm  = s[:judge_mean]
          hdr = "RECENT OUTCOMES (success_rate=#{(s[:success_rate] * 100).round(1)}%#{" judge_mean=#{jm}" if jm} over #{s[:total_outcomes]} attempts)"
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
          pool = outcomes(limit: 500, success: true).reject { |r| r[:session_id].to_s.empty? }
          scored = pool.map do |r|
            sim   = tokens.count { |t| r[:task].to_s.downcase.include?(t) }.to_f / tokens.length
            age_d = (now - Time.parse(r[:timestamp].to_s)) / 86_400.0
            decay = Math.exp(-age_d / 30.0)
            score = (r[:score] || 1.0).to_f
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

        public_class_method def self.export_finetune(opts = {})
          fmt       = (opts[:format] || :sharegpt).to_sym
          min_tools = (opts[:min_tools] || 1).to_i
          FileUtils.mkdir_p(FINETUNE_DIR)
          out = opts[:out] || File.join(FINETUNE_DIR, "pwn-#{Time.now.utc.strftime('%Y%m%d')}.jsonl")

          sids = outcomes(limit: 10_000, success: true).map { |r| r[:session_id] }.compact.uniq
          rows = 0
          File.open(out, 'w') do |f|
            sids.each do |sid|
              t = PWN::Sessions.load(session_id: sid)
              next if t.count { |e| e[:role].to_s == 'tool' } < min_tools

              conv = t.map { |e| { role: e[:role].to_s, content: e[:content].to_s } }
                      .reject { |e| e[:role] == 'system' && e[:content].start_with?('Session started') }
              line = case fmt
                     when :openai_jsonl then { messages: conv }
                     else { conversations: conv.map { |m| { from: sharegpt_role(role: m[:role]), value: m[:content] } } }
                     end
              f.puts(JSON.generate(line))
              rows += 1
            end
          end
          { path: out, format: fmt, sessions: sids.length, samples: rows, bytes: File.size(out) }
        end

        # Supported Method Parameters::
        # skill = PWN::AI::Agent::Learning.distill_skill(
        #   name: 'required - snake_case name for the new skill',
        #   session_id: 'optional - PWN::Sessions id to mine (uses its transcript)',
        #   content: 'optional - explicit markdown body; overrides transcript mining',
        #   references: 'optional - Array of reference URLs / CWE / CVE / ATT&CK ids'
        # )

        public_class_method def self.distill_skill(opts = {})
          name = opts[:name].to_s.gsub(/[^a-z0-9_-]/i, '_')
          raise 'ERROR: name is required' if name.empty?

          body = opts[:content].to_s
          body = build_skill_from_session(session_id: opts[:session_id], name: name) if body.strip.empty? && opts[:session_id]
          raise 'ERROR: content or session_id is required' if body.strip.empty?

          refs = Array(opts[:references]).map(&:to_s).map(&:strip).reject(&:empty?).uniq
          unless refs.empty?
            body = "---\nreferences:\n#{refs.map { |r| "  - #{r}" }.join("\n")}\n---\n#{body}" unless body.start_with?("---\n")
            body = "#{body.rstrip}\n\n## References\n#{refs.map { |r| "- #{r}" }.join("\n")}\n" unless body =~ /^\#{1,3}\s*References\s*$/i
          end

          dir = skills_dir
          FileUtils.mkdir_p(dir)
          path = File.join(dir, "#{name}.md")
          File.write(path, body)
          PWN::Config.load_skills(pwn_skills_path: dir) if defined?(PWN::Config) && PWN::Config.respond_to?(:load_skills)
          note_outcome(task: "distill_skill:#{name}", success: true, details: "Saved #{path}", tags: %w[skill auto])
          { saved: true, name: name, path: path, bytes: body.bytesize, references: refs }
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

          proxy_ok = infer_success(session_id: session_id, final: opts[:final])
          # S3 — tool-armed constitutional critic runs BEFORE the reward
          # model so its verdict is evidence, not hindsight.
          crit = defined?(Curriculum) ? Curriculum.critic(request: opts[:request], final: opts[:final], session_id: session_id) : { verdict: :pass }
          # R1 — LLM Outcome Reward Model (falls back to calibrated heuristic)
          v = Reward.judge(request: opts[:request], final: opts[:final], session_id: session_id, proxy_ok: proxy_ok) if defined?(Reward)
          v ||= { score: proxy_ok ? 1.0 : 0.0, success: proxy_ok, verdict: proxy_ok ? :solved : :wrong }
          v[:score] = [v[:score], 0.3].min if crit[:verdict] == :flaw
          ok = v[:score] >= 0.6

          # W1 — complete any pending (rejected, chosen) pair from a
          # user correction on the previous turn.
          pend = Thread.current[:pwn_pending_pref]
          if pend && ok && defined?(Reward)
            Reward.record_preference(prompt: pend[:prompt], rejected: pend[:rejected], chosen: opts[:final].to_s, source: :user_correction)
            Thread.current[:pwn_pending_pref] = nil
          end

          note_outcome(
            task: opts[:request].to_s[0, 120],
            success: ok,
            score: v[:score],
            details: "#{v[:verdict]}(#{v[:score].round(2)}) #{v[:rationale]} | #{opts[:final].to_s[0, 200]}",
            session_id: session_id,
            tags: ['auto', 'loop', v[:verdict].to_s]
          )
          # R2 — per-step credit assignment; C3 — HER on failure
          Reward.prm(request: opts[:request], session_id: session_id) if defined?(Reward) && ok
          Curriculum.hindsight(request: opts[:request], final: opts[:final], session_id: session_id) if !ok && defined?(Curriculum)
          # W3 — calibration: predicted (from plan_first) vs actual
          Curriculum.calibrate(predicted: opts[:predicted], actual: v[:score], engine: PWN::Env.dig(:ai, :active)) if opts[:predicted] && defined?(Curriculum)
          reflect(session_id: session_id) if ok
          Reward.sentinel if defined?(Reward)
          Extrospection.auto_extrospect(session_id: session_id) if defined?(Extrospection)
        rescue StandardError => e
          warn "[pwn-ai/learning] auto_introspect swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Learning.flip_last_outcome(
        #   session_id: 'optional - only flip if the newest outcome belongs to this session',
        #   reason: 'optional - why it is being flipped (usually the user correction text)'
        # )
        #
        # Rewrites the most-recently-appended learning.jsonl entry from
        # success:true to success:false. Called by Mistakes.check_user_correction
        # when the user's next message rejects the previous answer, so the
        # 100 %-success illusion is broken and the failure enters the corpus.

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
          # W1 — the (rejected_prev_answer, chosen_next_answer) pair is
          # captured by Mistakes.check_user_correction which has both.
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

          mem = PWN::Memory.load
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
            sorted = mem.sort_by do |_k, v|
              age_d = (now - Time.parse(v[:timestamp].to_s)) / 86_400.0
              ttl_d = (v[:ttl].to_f / 86_400.0)
              imp   = (v[:importance] || 0.5).to_f.clamp(0.05, 1.0)
              conf  = (v[:confidence] || (v[:source].to_s == 'human' ? 0.95 : 0.5)).to_f.clamp(0.05, 1.0)
              staleness = ttl_d.positive? ? age_d / ttl_d : age_d / 90.0
              -(staleness / (imp * conf))
            rescue StandardError
              0.0
            end
            drop = sorted.first(mem.size - cap).map(&:first)
            drop.each { |k| mem.delete(k) }
            removed.concat(drop)
          end
          PWN::Memory.save(mem: mem)
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

        # Auto fact-check post-filter: local models hallucinate CVEs /
        # versions ~5-10x more than frontier ones. When the active engine is
        # :ollama, scan the final for CVE / version-shaped claims and hand
        # each to Extrospection.verify - refuted claims become
        # Mistakes(tool:'assumption') so KNOWN MISTAKES warns every future
        # run off that specific hallucination.
        private_class_method def self.fact_check_local_final(opts = {})
          return unless defined?(PWN::Env) && PWN::Env.dig(:ai, :active).to_s.downcase.to_sym == :ollama
          return unless defined?(Extrospection) && Extrospection.respond_to?(:verify)

          claims = opts[:final].to_s.scan(CLAIM_RX).flatten.compact.uniq.first(3)
          claims.each { |c| Extrospection.verify(claim: c, commit: true) }
        rescue StandardError => e
          warn "[pwn-ai/learning] fact_check swallowed: #{e.class}: #{e.message}"
        end

        private_class_method def self.compress_exemplar(opts = {})
          sid = opts[:session_id]
          cap = opts[:max_msgs] || 6
          t = PWN::Sessions.load(session_id: sid)
          user = t.find  { |e| e[:role].to_s == 'user' }
          fin  = t.rfind { |e| e[:role].to_s == 'assistant' }
          return [] unless user && fin

          # C4 — minimal sufficient trace: prefer steps PRM tagged reward>0
          tools = t.select { |e| e[:role].to_s == 'tool' }
          rewarded = tools.select { |e| e[:step_reward].to_i.positive? }
          tools = rewarded unless rewarded.empty?
          tools = tools.first([cap - 2, 0].max)
          msgs  = [{ role: 'user', content: "[exemplar] #{user[:content].to_s[0, 400]}" }]
          tools.each { |e| msgs << { role: 'assistant', content: "[exemplar tool] #{e[:content].to_s[0, 300]}" } }
          msgs << { role: 'assistant', content: "[exemplar final] #{fin[:content].to_s[0, 400]}" }
          msgs
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
        # PWN::AI::Agent::Learning.purge_noise
        #
        # One-shot GC of the pre-R1 garbage: drops every PWN::Memory entry
        # matching the old `SUCCESS: <req> — <final>` / `Avoid repeating
        # failure pattern from <tool>: {"success":true` shapes. Run once
        # after upgrading; subsequent writes never produce these.

        public_class_method def self.purge_noise
          return { removed: 0 } unless defined?(PWN::Memory)

          mem = PWN::Memory.load
          before = mem.size
          mem.reject! do |_k, v|
            next false unless v[:category].to_s == 'lesson'

            val = v[:value].to_s
            val.start_with?('SUCCESS: ', 'FAILURE: ') ||
              val.match?(/\AAvoid repeating failure pattern from \w+: .{0,5}\{"success":true/)
          end
          PWN::Memory.save(mem: mem)
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
              PWN::AI::Agent::Learning.purge_noise                            # one-shot GC of pre-R1 garbage lessons
              PWN::AI::Agent::Learning.to_context(limit: 5)                  # injected by PromptBuilder
              PWN::AI::Agent::Learning.stats
              PWN::AI::Agent::Learning.reset

              Enable end-of-run auto-learning with:
                PWN::Env[:ai][:agent][:auto_introspect] = true

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
