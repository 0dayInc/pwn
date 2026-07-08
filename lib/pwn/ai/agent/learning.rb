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
      #   Loop.run --(final answer)----> Learning.auto_reflect (opt-in)
      #   model    --(tool calls)------> learning_note_outcome / _distill_skill
      #   PromptBuilder <----------------- Learning.to_context + Metrics.to_context
      #
      # Everything is file-backed under ~/.pwn so it survives across REPL
      # restarts and is shared by every future session.
      module Learning
        LEARNING_FILE = File.join(Dir.home, '.pwn', 'learning.jsonl')
        MAX_MEMORY_ENTRIES = 200

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
          FileUtils.mkdir_p(File.dirname(LEARNING_FILE))
          File.open(LEARNING_FILE, 'a') { |f| f.puts(JSON.generate(entry)) }

          key = :"lesson_#{entry[:id]}"
          cat = :lesson
          val = "#{success ? 'SUCCESS' : 'FAILURE'}: #{task} — #{opts[:details].to_s.strip[0, 200]}"
          PWN::Memory.remember(key: key, value: val, category: cat) if defined?(PWN::Memory)

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
          skills = defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) ? PWN::Skills.keys.length : 0
          mem    = defined?(PWN::Memory) ? PWN::Memory.load.keys.length : 0
          {
            total_outcomes: total,
            successes: ok,
            failures: total - ok,
            success_rate: total.positive? ? (ok.to_f / total).round(3) : 0.0,
            skills_known: skills,
            memory_entries: mem,
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
          hdr = "RECENT OUTCOMES (success_rate=#{(s[:success_rate] * 100).round(1)}% over #{s[:total_outcomes]} attempts)"
          out = "#{hdr}\n#{rows.map(&fmt).join("\n")}\n"
          out += "RECENT FAILURES (learn from these — do not repeat)\n#{fails.map(&fmt).join("\n")}\n" unless fails.empty?
          "#{out}\n"
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
        # Uses PWN::AI::Agent::Introspection (when available) to LLM-summarise the
        # session into structured lessons. Falls back to a heuristic
        # extractor when introspection is disabled so learning never stops.

        public_class_method def self.reflect(opts = {})
          session_id = opts[:session_id]
          dry_run    = opts[:dry_run] ? true : false
          raise 'ERROR: session_id is required' if session_id.to_s.empty?

          transcript = PWN::Sessions.load(session_id: session_id)
          return { session_id: session_id, lessons: [], reason: 'empty transcript' } if transcript.empty?

          lessons = introspective_lessons(transcript: transcript)
          lessons = heuristic_lessons(transcript: transcript) if lessons.empty?

          saved = []
          lessons.each do |l|
            next if l.to_s.strip.empty?

            key = :"reflect_#{session_id}_#{Digest::SHA256.hexdigest(l)[0, 8]}"
            PWN::Memory.remember(key: key, value: l, category: :lesson) unless dry_run
            saved << { key: key, lesson: l }
          end
          consolidate unless dry_run

          { session_id: session_id, lessons: saved, count: saved.length, dry_run: dry_run }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Learning.auto_reflect(
        #   session_id: 'required - id of the just-completed session',
        #   request: 'optional - original user request (for outcome logging)',
        #   final: 'optional - final assistant answer (for outcome logging)'
        # )
        #
        # Called by Loop.run when PWN::Env[:ai][:agent][:auto_reflect] is
        # truthy. Never raises — learning must not break the primary loop.

        public_class_method def self.auto_reflect(opts = {})
          session_id = opts[:session_id]
          return unless session_id
          return unless auto_reflect_enabled?

          ok = infer_success(session_id: session_id, final: opts[:final])
          note_outcome(
            task: opts[:request].to_s[0, 120],
            success: ok,
            details: opts[:final].to_s[0, 300],
            session_id: session_id,
            tags: %w[auto loop]
          )
          reflect(session_id: session_id)
          Extrospection.auto_extrospect(session_id: session_id) if defined?(Extrospection)
        rescue StandardError => e
          warn "[pwn-ai/learning] auto_reflect swallowed: #{e.class}: #{e.message}"
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
          lines[-1] = "#{JSON.generate(last)}\n"
          File.write(LEARNING_FILE, lines.join)
          { flipped: true, id: last[:id] }
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
          seen = {}
          removed = []
          mem.each do |k, v|
            sig = Digest::SHA256.hexdigest(v[:value].to_s.strip.downcase)[0, 16]
            if seen[sig]
              removed << k
            else
              seen[sig] = k
            end
          end
          removed.each { |k| mem.delete(k) }

          if mem.size > cap
            sorted = mem.sort_by { |_k, v| v[:timestamp].to_s }
            drop   = sorted.first(mem.size - cap).map(&:first)
            drop.each { |k| mem.delete(k) }
            removed.concat(drop)
          end
          PWN::Memory.save(mem: mem)
          { removed: removed.length, remaining: mem.size }
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

        private_class_method def self.auto_reflect_enabled?
          return false unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          PWN::Env.dig(:ai, :agent, :auto_reflect) ? true : false
        rescue StandardError
          false
        end

        FAILURE_FINAL_RX = /\[pwn-ai\] (iteration budget exhausted|engine returned no message)|\b(i (was )?unable to|i could not|i couldn'?t|cannot proceed|failed to)\b/i

        # Derive a success signal stronger than "final answer non-empty":
        # look at the tool-failure ratio inside the just-completed turn AND
        # scan the final text for self-reported failure language. Without
        # this, auto_reflect logs ~100 % success and the negative-feedback
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

          bad = tool.count { |e| e[:content].to_s.include?('"success":false') || e[:content].to_s.match?(/"exit":[1-9]/) }
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
          return [] unless defined?(PWN::AI::Agent::Introspection)
          return [] unless defined?(PWN::Env) && PWN::Env.is_a?(Hash) && PWN::Env.dig(:ai, :introspection)

          req = "Analyse this pwn-ai session transcript and emit up to 5 durable, generalizable lessons (one per line, no numbering, imperative voice) that would make future runs faster or more reliable. Focus on tool selection, error recovery, and target-agnostic technique. Ignore trivia.\n\nTRANSCRIPT:\n#{transcript_text(transcript: transcript)}"
          resp = PWN::AI::Agent::Introspection.reflect_on(request: req, suppress_pii_warning: true)
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

            if c.include?('"success":false') || c.match?(/error|Error|ERROR/)
              tool = c[/^(\w+) →/, 1] || c[/"error":"([^"]{5,120})"/, 1] || 'tool'
              lessons << "Avoid repeating failure pattern from #{tool}: #{c[0, 160]}"
            end
          end
          if lessons.empty?
            asst = transcript.rfind { |e| e[:role].to_s == 'assistant' }
            lessons << "Approach that worked: #{asst[:content].to_s.strip[0, 200]}" if asst && !asst[:content].to_s.strip.empty?
          end
          lessons.uniq.first(5)
        end

        private_class_method def self.build_skill_from_session(opts = {})
          session_id = opts[:session_id]
          name       = opts[:name]
          transcript = PWN::Sessions.load(session_id: session_id)
          steps = transcript.select { |e| %w[tool assistant].include?(e[:role].to_s) }
                            .map { |e| "- **#{e[:role]}**: #{e[:content].to_s.strip[0, 300]}" }
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
              PWN::AI::Agent::Learning.auto_reflect(session_id: sid, request: req, final: text)
              PWN::AI::Agent::Learning.distill_skill(name: 'quick_recon', session_id: sid)
              PWN::AI::Agent::Learning.consolidate(max_entries: 200)         # dedupe + prune Memory
              PWN::AI::Agent::Learning.to_context(limit: 5)                  # injected by PromptBuilder
              PWN::AI::Agent::Learning.stats
              PWN::AI::Agent::Learning.reset

              Enable end-of-run auto-learning with:
                PWN::Env[:ai][:agent][:auto_reflect] = true

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
