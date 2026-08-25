# frozen_string_literal: true

require 'json'

module PWN
  module AI
    module Agent
      # High-level executive brief of the work the agent is about to do.
      #
      # Every pwn-ai request is a goal. There is no statement/question/goal
      # request type. English tangible tasks are an advisory compass:
      #   1. plan(request:) — break the goal into ordered plain-English tasks
      #   2. about_to(tools:) — per tool-batch brief led by "task k/n"
      #   3. active_task_prompt — injected into Loop as a compass only
      #   4. record! emits an advancement brief when plan_idx moves
      #
      # Never dumps raw commands or tool results into the task row — those
      # stay on the per-tool lines the REPL already prints.
      #
      # REPL on_tool contract (repl.rb):
      #   on_tool.call('task', full_summary_text, '')  # result MUST be empty
      #   # → [ ts → pwn-ai → task ] <full summary, no truncation>
      #   on_tool.call('shell', args, result)          # real tool
      module TaskSummarizer
        DEFAULT_EVERY = 5
        DEFAULT_INTERVAL_S = 8.0
        MAX_BUFFER = 64
        # Soft cap only for non-plan batch briefs when NOT showing full.
        # Plan text and task summaries are always shown in full (no ellipsis).
        PREVIEW_LEN = 2_000
        MAX_PLAN_TASKS = 12
        MIN_PLAN_TASKS = 2

        ENGINE_MODS = {
          openai: 'PWN::AI::OpenAI',
          grok: 'PWN::AI::Grok',
          ollama: 'PWN::AI::Ollama',
          openwebui: 'PWN::AI::OpenWebUI',
          anthropic: 'PWN::AI::Anthropic',
          gemini: 'PWN::AI::Gemini'
        }.freeze

        PLAN_SYSTEM = <<~SYS
          You are the pwn-ai Task Planner.
          Break the user request into an ordered list of tangible work units. Rules:
          - 2..12 tasks. Each task is one coherent unit of work (may need many tools).
          - Plain US English. Imperative mood. No tool names, paths, or shell commands.
          - Cover discovery/recon, the core work, verification, and the requested
            deliverable/format ONLY when relevant to THIS request.
          - Tailor steps to THIS request only — do not reuse a canned domain script.
          - Last task should verify or present the final result when that fits.
          - Never append unrelated repo hygiene (rubocop/rake/docs) unless the user
            asked to change code under /opt/pwn.
          - Only plan live discovery/recon when the user asked to scan/find live hosts.
          - Output ONLY a JSON array of strings. No markdown, no prose, no keys.
          Example: ["determine the local IPv4 subnet","find live hosts on that subnet","present live hosts as JSON"]
        SYS

        public_class_method def self.enabled?
          v = PWN::Env.dig(:ai, :agent, :task_summary)
          v.nil? || !!v
        rescue StandardError
          true
        end

        public_class_method def self.verbose?
          !!PWN::Env.dig(:ai, :agent, :task_summary_verbose)
        rescue StandardError
          false
        end

        # LLM plan generation is on by default. Set
        # PWN::Env[:ai][:agent][:task_summary_llm] = false to force the
        # offline generic fallback (tests / air-gapped).
        public_class_method def self.llm_plan_enabled?
          v = PWN::Env.dig(:ai, :agent, :task_summary_llm)
          v.nil? || !!v
        rescue StandardError
          true
        end

        public_class_method def self.every_n
          n = PWN::Env.dig(:ai, :agent, :task_summary_every)
          n = DEFAULT_EVERY if n.nil?
          [n.to_i, 1].max
        rescue StandardError
          DEFAULT_EVERY
        end

        public_class_method def self.interval_s
          t = PWN::Env.dig(:ai, :agent, :task_summary_interval_s)
          t = DEFAULT_INTERVAL_S if t.nil?
          [t.to_f, 1.0].max
        rescue StandardError
          DEFAULT_INTERVAL_S
        end

        # Per-run state (also safe for nested/swarm if callers keep their own hash)
        # Supported Method Parameters::
        # state = PWN::AI::Agent::TaskSummarizer.fresh(
        #   request: 'optional - original user goal string'
        # )
        public_class_method def self.fresh(opts = {})
          req = canonical_request(request: opts[:request])
          req = opts[:request].to_s if req.empty?
          {
            request: req,
            original_request: req,
            events: [],
            since_emit: 0,
            last_emit_at: Time.now,
            total: 0,
            counts: Hash.new(0),
            last_brief: nil,
            last_brief_fp: nil,
            pending_tools: [],
            emitted_for_batch: false,
            plan: [],
            plan_emitted: false,
            plan_text: nil,
            plan_idx: 0,
            batch_seq: 0,
            plan_source: nil,
            # RL-adjacent executive state (index only — credit lives in Reward)
            prm_pos_streak: 0,
            last_prm_signal: nil,
            unified_from: nil,
            # English-task-as-primary steering / advancement UX
            focus_injected_idx: nil,
            last_advanced_from: nil,
            last_advance_brief: nil,
            tools_on_task: 0,
            evidence_blob: ''
          }
        end

        # Map a tool name to a short human capability label (no args).
        private_class_method def self.capability_label(opts = {})
          tool = opts[:name].to_s
          case tool
          when 'shell' then 'run shell commands'
          when 'pwn_eval' then 'evaluate Ruby in the live PWN namespace'
          when /^memory_/ then 'read or write durable memory'
          when /^sessions_/ then 'inspect prior session transcripts'
          when /^mistakes_/ then 'review or resolve known mistakes'
          when /^learning_/ then 'record learning outcomes or reflect'
          when /^extro_/ then 'sense or verify the external environment'
          when /^skill_/ then 'read or author reusable skills'
          when /^agent_/, /^swarm_/ then 'coordinate multi-agent personas'
          when /^cron_/ then 'manage scheduled jobs'
          when /^reward_/, /^curriculum_/ then 'score outcomes or train curriculum'
          when /^metrics_/ then 'inspect tool telemetry'
          else "use #{tool}"
          end
        rescue StandardError
          "use #{opts[:name]}"
        end

        # Group tool names into ordered unique capability phrases.
        private_class_method def self.capabilities_for(opts = {})
          Array(opts[:names]).map { |n| capability_label(name: n) }.uniq
        end

        # "shell×3, pwn_eval×1" — distinctive when only tools change.
        private_class_method def self.tool_counts_phrase(opts = {})
          counts = Hash.new(0)
          Array(opts[:names]).each { |n| counts[n.to_s] += 1 if n.to_s != '' }
          return '' if counts.empty?

          counts.map { |n, c| c > 1 ? "#{n}×#{c}" : n }.join(', ')
        rescue StandardError
          Array(opts[:names]).map(&:to_s).reject(&:empty?).join(', ')
        end

        # Short intent verbs from tool args (no paths/commands dumped).
        # Makes two shell batches distinguishable (search vs edit vs test).
        private_class_method def self.intent_phrase(opts = {})
          intents = []
          Array(opts[:tools]).each do |tool|
            name = tool[:name].to_s
            args = tool[:args]
            sample =
              case args
              when String then args
              when Hash
                prefer = %w[command code query claim url request path file text prompt ruby script id name task]
                (prefer.map { |k| args[k] || args[k.to_sym] }.compact.first || args.values.compact.first).to_s
              else
                args.to_s
              end
            sample = sample.to_s.gsub(/\s+/, ' ').strip.downcase
            next if sample.empty?

            verb =
              case name
              when 'shell'
                case sample
                when /\b(rg|grep|find|ag|ack)\b/ then 'search'
                when /\b(sed|ruby -i|perl -i|patch|tee |>>|printf |> )/ then 'edit'
                when /\b(cat|sed -n|head|tail|less|wc |file |stat |ls\b)/ then 'read'
                when /\b(rspec|rake|rubocop|pytest|npm test|cargo test)\b/ then 'test'
                when /\b(git |gh )\b/ then 'vcs'
                when /\b(curl|wget|http)/ then 'fetch'
                when /\b(python|ruby|node|bash|sh )\b/ then 'script'
                else 'run'
                end
              when 'pwn_eval'
                case sample
                when /transparentbrowser|\.goto\b|browser_obj|dump_links|headless/ then 'browse'
                when /\b(write|file\.|fileutils|binwrite)\b/ then 'mutate-ruby'
                when /\b(load |require |const_get|method_list|instance_methods)\b/ then 'introspect-ruby'
                else 'eval-ruby'
                end
              when /^memory_/ then 'memory'
              when /^sessions_/ then 'sessions'
              when /^mistakes_/ then 'mistakes'
              when /^learning_/ then 'learning'
              when /^extro_/ then 'extrospect'
              when /^skill_/ then 'skills'
              when /^reward_/, /^curriculum_/ then 'reward'
              else name.tr('_', '-')
              end
            intents << verb
          end
          intents.uniq.first(6).join('+')
        rescue StandardError
          ''
        end

        private_class_method def self.brief_fingerprint(opts = {})
          opts[:line].to_s.gsub(/\s+/, ' ').strip.downcase
        rescue StandardError
          opts[:line].to_s
        end

        # True when this brief is effectively the same task line we already showed.
        # A1: also cross-dedup against the full plan blob so about_to cannot
        # restate text emit_plan! just printed (plan vs about_to FPs differ).
        private_class_method def self.duplicate_brief?(opts = {})
          state = opts[:state]
          line = opts[:line]
          return false unless state.is_a?(Hash)

          fp = brief_fingerprint(line: line)
          return false if fp.empty?
          return true if state[:last_brief_fp] == fp

          # Near-duplicate of the full plan blob (should not happen, but cheap).
          plan_fp = brief_fingerprint(line: state[:plan_text])
          return true if !plan_fp.empty? && fp == plan_fp

          false
        rescue StandardError
          false
        end

        private_class_method def self.remember_brief!(opts = {})
          state = opts[:state]
          line = opts[:line]
          return line unless state.is_a?(Hash)

          state[:last_brief] = line
          state[:last_brief_fp] = brief_fingerprint(line: line)
          state[:batch_seq] = state[:batch_seq].to_i + 1
          line
        rescue StandardError
          line
        end

        # Every request gets a task compass. There is no request type.
        public_class_method def self.needs_task_breakdown?(opts = {})
          return true if opts.is_a?(Hash)

          true
        end

        # ------------------------------------------------------------------
        # Request → ordered tangible tasks (each may map to many tools).
        # Called once when the user submits a request.
        #
        # Priority:
        #   1. Explicit numbered / bulleted steps already in the request
        #   2. Active LLM decomposition (works for ANY request)
        #   3. Thin generic offline fallback (never domain hardcoding)
        #
        # Supported Method Parameters::
        # tasks = PWN::AI::Agent::TaskSummarizer.plan(
        #   request: 'required - user goal string',
        #   state: 'optional - fresh() hash to mutate',
        #   tasks: 'optional - injected plan array (tests)',
        #   llm_tasks: 'optional - injected LLM task array (tests)'
        # )
        # ------------------------------------------------------------------
        public_class_method def self.plan(opts = {})
          raw = opts[:request].to_s
          raw = (opts[:state][:original_request] || opts[:state][:request]).to_s if raw.strip.empty? && opts[:state].is_a?(Hash)
          goal = canonical_request(request: raw)
          goal = raw.gsub(/\s+/, ' ').strip if goal.empty?
          return [] if goal.empty?

          if defined?(PWN::AI::Agent::Loop) &&
             PWN::AI::Agent::Loop.respond_to?(:world_knowledge?) &&
             !opts.key?(:tasks) && !opts.key?(:llm_tasks) &&
             PWN::AI::Agent::Loop.world_knowledge?(request: goal)
            if opts[:state].is_a?(Hash)
              opts[:state][:plan] = []
              opts[:state][:plan_source] = :no_host_work
            end
            return []
          end

          source = nil
          tasks = []

          # Prefer explicit enumerated steps already in the request (1. / 2. / - ).
          enumerated = extract_enumerated_steps(goal: goal)
          if enumerated.length >= MIN_PLAN_TASKS
            tasks = enumerated
            source = :enumerated
          elsif opts.key?(:tasks)
            # Caller-injected plan (tests / precomputed).
            tasks = Array(opts[:tasks]).map { |t| t.to_s.strip }.reject(&:empty?)
            source = :injected
          else
            tasks = llm_decompose(goal: goal, llm_tasks: opts[:llm_tasks], has_llm_tasks: opts.key?(:llm_tasks))
            source = tasks.any? ? :llm : nil
            if tasks.length < MIN_PLAN_TASKS
              tasks = fallback_decompose(goal: goal)
              source = :fallback
            end
          end

          tasks = normalize_task_list(tasks: tasks, goal: goal)
          if opts[:state].is_a?(Hash)
            opts[:state][:plan] = tasks
            opts[:state][:original_request] = goal if opts[:state][:original_request].to_s.empty?
            opts[:state][:request] = goal if opts[:state][:request].to_s.empty?
            opts[:state][:plan_source] = source
          end
          tasks
        rescue StandardError
          goal = opts[:request].to_s.gsub(/\s+/, ' ').strip
          if goal.empty?
            opts[:state][:plan] = [] if opts[:state].is_a?(Hash)
            []
          else
            normalize_task_list(tasks: ["Carry out: #{goal}"], goal: goal)
          end
        end

        private_class_method def self.howto_goal?(opts = {})
          goal = opts[:goal].to_s
          return true if defined?(PWN::AI::Agent::Loop) &&
                         PWN::AI::Agent::Loop.respond_to?(:request_intent) &&
                         PWN::AI::Agent::Loop.request_intent(request: goal) == :howto

          goal.match?(/\b(how\s+to|how\s+do\s+i|how\s+can\s+i|syntax|usage of|explain how|show me how)\b/i)
        rescue StandardError
          false
        end

        private_class_method def self.normalize_task_list(opts = {})
          goal = opts[:goal]
          list = Array(opts[:tasks]).map { |t| t.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?).uniq
          list = ["Carry out: #{goal}"] if list.empty?
          # Strip contaminated repo-hygiene tasks on non-code requests.
          unless goal.to_s.match?(%r{\b(rubocop|rake|rspec|/opt/pwn|refactor|patch|commit|documentation)\b}i)
            list.reject! { |t| t.match?(/\b(rubocop|rvmsudo\s+rake|bundle\s+exec\s+rake|fix rake|lint offenses)\b/i) }
            list = ["Carry out: #{goal}"] if list.empty?
          end
          # How-to: keep explanation-only plan; never force recon/verify thrash.
          if howto_goal?(goal: goal)
            list = list.first(2)
            list = ['Explain the requested tool usage with concrete examples', 'Present the answer clearly'] if list.empty?
            return list.first(MAX_PLAN_TASKS)
          end
          # Close with a present/report step — never a test-runner verify.
          # Appending "Verify the result…" used to classify as :verify and
          # block Loop.run until rspec/rubocop printed 0 failures.
          list << 'Present the result and report completion' unless list.last.to_s.match?(
            /verif|test|confirm|rubocop|rake|accept|done|close|summar|json|yaml|table|present|format|convert|report completion|report results/i
          )
          list.first(MAX_PLAN_TASKS)
        end

        # Format the full plan as the task-summary body (shown in entirety).
        # Uses "task k/n: ..." so emit_plan! and about_to share one vocabulary.
        #
        # Supported Method Parameters::
        # text = PWN::AI::Agent::TaskSummarizer.format_plan(
        #   tasks: 'required - Array of task strings',
        #   request: 'optional - goal string'
        # )
        public_class_method def self.format_plan(opts = {})
          list = Array(opts[:tasks]).map(&:to_s).reject(&:empty?)
          goal = opts[:request].to_s.gsub(/\s+/, ' ').strip
          return '' if list.empty?

          n = list.length
          lines = []
          lines << "Goal: #{goal}" unless goal.empty?
          lines << "Tangible tasks (#{n}) — each task may leverage one or more tools to complete its objective(s):"
          list.each_with_index do |t, i|
            lines << "  task #{i + 1}/#{n}: #{t}"
          end
          lines.join("\n")
        rescue StandardError
          list = Array(opts[:tasks])
          n = list.length
          list.map.with_index(1) { |t, i| "task #{i}/#{n}: #{t}" }.join("\n")
        end

        public_class_method def self.emit_plan!(opts = {})
          state = opts[:state]
          return nil unless state.is_a?(Hash)
          return state[:plan_text] if state[:plan_emitted] && !state[:plan_text].nil?

          request = state[:original_request].to_s
          request = state[:request].to_s if request.empty?
          request = opts[:request].to_s if request.empty?
          request = canonical_request(request: request)
          request = opts[:request].to_s.gsub(/\s+/, ' ').strip if request.empty?
          tasks = state[:plan]
          tasks = plan(request: request, state: state) if tasks.nil? || Array(tasks).empty?
          text = format_plan(tasks: tasks, request: request)
          state[:plan] = Array(tasks)
          state[:plan_text] = text
          state[:plan_emitted] = true
          state[:plan_idx] = 0
          # Still remember brief so about_to de-dup works; empty text is ok.
          remember_brief!(state: state, line: text) unless text.to_s.empty?
          # Return nil only when completely empty (no kind banner either).
          text.to_s.empty? ? nil : text
        rescue StandardError
          nil
        end

        private_class_method def self.extract_enumerated_steps(opts = {})
          goal = opts[:goal].to_s
          # "1. foo 2. bar" or newline "1) foo\n2) bar" or "- foo\n- bar"
          chunks = []
          if goal.include?("\n")
            goal.split(/\n+/).each do |ln|
              ln = ln.strip
              next if ln.empty?

              if (m = ln.match(/\A(?:\d+[.):]|[-*•])\s+(.+)\z/))
                chunks << m[1].strip
              elsif chunks.any?
                chunks << ln
              end
            end
          end
          if chunks.length < MIN_PLAN_TASKS
            # Inline: "1. do X 2. do Y 3. do Z"
            inline = goal.scan(/(?:^|\s)\d+[.):]\s+([^\d]+?)(?=(?:\s+\d+[.):]\s+)|$)/)
            chunks = inline.flatten.map(&:strip) if inline.length >= MIN_PLAN_TASKS
          end
          if chunks.length < MIN_PLAN_TASKS
            # Numbered improvement list like "1. the task ... 2. once a request"
            inline = goal.split(/(?=(?:^|\s)\d+\.\s+)/).map(&:strip).reject(&:empty?)
            chunks = inline.map { |c| c.sub(/\A\d+\.\s+/, '') }.reject(&:empty?) if inline.length >= MIN_PLAN_TASKS
          end
          reject_scaffold_tasks(tasks: chunks)
        rescue StandardError
          []
        end

        # ------------------------------------------------------------------
        # LLM-backed decomposition for arbitrary requests.
        # ------------------------------------------------------------------
        private_class_method def self.llm_decompose(opts = {})
          return [] unless llm_plan_enabled?
          return Array(opts[:llm_tasks]) if opts[:has_llm_tasks]

          raw = chat_for_plan(request: opts[:goal])
          return [] if raw.to_s.strip.empty?

          parse_llm_tasks(raw: raw)
        rescue StandardError => e
          warn "[pwn-ai/task_summarizer] llm_decompose swallowed: #{e.class}: #{e.message}"
          []
        end

        # Prefer Reflect when module_reflection is on (teacher engine / gated).
        # Reflect.on uses direct engine .chat (never Loop.run) + depth guard,
        # so this cannot re-enter via emit_plan! / after_read.
        #
        # Supported Method Parameters::
        # text = PWN::AI::Agent::TaskSummarizer.chat_for_plan(
        #   request: 'required - user goal to decompose'
        # )
        # Kept public so specs can stub the LLM boundary.
        public_class_method def self.chat_for_plan(opts = {})
          goal = opts[:request].to_s
          system = PLAN_SYSTEM
          user = "USER REQUEST:\n#{goal}\n\nReturn ONLY a JSON array of tangible task strings."
          if reflect_available?
            resp = Reflect.on(
              request: user,
              system_role_content: system,
              suppress_pii_warning: true,
              spinner: false,
              timeout: sidecar_timeout,
              quiet: true
            )
            text = reflect_text(resp: resp)
            return text unless text.to_s.strip.empty?
          end

          # Fallback: active engine text chat (no tools). Used when reflection
          # is off, re-entrancy returned nil, or Reflect yielded empty.
          engine_chat(request: user, system_role_content: system)
        rescue StandardError => e
          warn "[pwn-ai/task_summarizer] chat_for_plan swallowed: #{e.class}: #{e.message}"
          ''
        end

        private_class_method def self.reflect_available?
          return false unless defined?(Reflect)
          return false unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          !!PWN::Env.dig(:ai, :module_reflection)
        rescue StandardError
          false
        end

        private_class_method def self.reflect_text(opts = {})
          resp = opts[:resp]
          case resp
          when String then resp
          when Hash
            (
              resp[:content] || resp['content'] ||
              resp.dig(:choices, -1, :content) || resp.dig(:choices, -1, :text) ||
              resp.dig('choices', -1, 'content') || resp.dig('choices', -1, 'text') ||
              resp[:reply] || resp['reply'] || resp[:final] || resp['final']
            ).to_s
          else
            resp.to_s
          end
        end

        private_class_method def self.engine_chat(opts = {})
          engine = active_engine
          mod_name = ENGINE_MODS[engine]
          return '' unless mod_name

          mod = Object.const_get(mod_name)
          return '' unless mod.respond_to?(:chat)

          r = mod.chat(
            request: opts[:request],
            system_role_content: opts[:system_role_content],
            spinner: false,
            timeout: sidecar_timeout,
            quiet: true
          )
          reflect_text(resp: r)
        rescue StandardError => e
          warn "[pwn-ai/task_summarizer] engine_chat swallowed: #{e.class}: #{e.message}"
          ''
        end

        private_class_method def self.active_engine
          eng = PWN::Env.dig(:ai, :active).to_s.downcase.to_sym
          ENGINE_MODS.key?(eng) ? eng : :ollama
        rescue StandardError
          :ollama
        end

        # Kind / plan classification is a sidecar hop. Bound it so a hung
        # model cannot stall the user's real answer, and stay quiet on timeout.
        private_class_method def self.sidecar_timeout
          n = (PWN::Env.dig(:ai, :agent, :sidecar_llm_timeout) if defined?(PWN::Env)).to_i
          n = 180 if n < 30
          n = 180 if n > 180
          n
        rescue StandardError
          20
        end

        # Parse JSON array, fenced JSON, or numbered/bulleted plain text.
        #
        # Supported Method Parameters::
        # tasks = PWN::AI::Agent::TaskSummarizer.parse_llm_tasks(
        #   raw: 'required - raw LLM response text'
        # )
        # Public so unit tests can exercise the parser without network I/O.
        public_class_method def self.parse_llm_tasks(opts = {})
          text = opts[:raw].to_s.strip
          return [] if text.empty?

          # Strip thinking blocks some local models emit.
          text = text.gsub(%r{<think>.*?</think>}mi, '').strip
          text = text.sub(/\A```(?:json)?\s*/i, '').sub(/\s*```\z/, '').strip

          json_blob = text[/\[.*\]/m]
          if json_blob
            begin
              parsed = JSON.parse(json_blob)
              if parsed.is_a?(Array)
                tasks = parsed.map do |item|
                  case item
                  when String then item
                  when Hash then (item['task'] || item[:task] || item['text'] || item[:text] || item.values.first).to_s
                  else item.to_s
                  end
                end
                cleaned = tasks.map { |t| t.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?)
                return cleaned if cleaned.length >= MIN_PLAN_TASKS
              end
            rescue JSON::ParserError
              # fall through to line parse
            end
          end

          lines = text.split(/\n+/).map(&:strip).reject(&:empty?)
          tasks = lines.filter_map do |ln|
            next if ln.match?(/\A[\[\]{},]\z/)
            next if ln.match?(/\A(?:here|tasks?|plan|json)\b/i) && ln.length < 40

            ln = ln.sub(/\A(?:\d+[.):]|[-*•])\s+/, '')
            ln = ln.sub(/\A["']/, '').sub(/["']\s*,?\s*\z/, '')
            ln = ln.sub(/,\s*\z/, '').strip
            next if ln.empty? || ln.length < 3
            next if ln.start_with?('[', '{')

            ln
          end
          tasks.uniq
        rescue StandardError
          []
        end

        # Thin offline fallback when the LLM is disabled or unavailable.
        # Intentionally generic — NO static per-domain task scripts.
        #
        # Supported Method Parameters::
        # tasks = PWN::AI::Agent::TaskSummarizer.fallback_decompose(
        #   goal: 'required - user goal string'
        # )
        public_class_method def self.fallback_decompose(opts = {})
          goal_text = canonical_request(request: opts[:goal])
          goal_text = opts[:goal].to_s if goal_text.empty?
          goal_lc = goal_text.downcase
          tasks = []

          # If the operator already spelled improvement bullets, surface them.
          bullets = goal_text.scan(/(?:^|\s)(?:\d+\.|[-*])\s*([^.;]+)/).flatten.map(&:strip)
          bullets = reject_scaffold_tasks(tasks: bullets)
          if bullets.length >= MIN_PLAN_TASKS
            bullets.first(8).each { |b| tasks << b.sub(/\Athe\s+/i, '').sub(/\.\s*\z/, '') }
            return tasks
          end

          if howto_goal?(goal: goal_text)
            return [
              'Explain the requested tool usage with concrete examples',
              'Present the answer clearly'
            ]
          end

          artifact = goal_text[%r{(?:/(?:tmp|var|home|opt|usr)/\S+\.(?:pdf|html|md|json|txt|csv)|~/\S+\.(?:pdf|html|md|json|txt|csv))}i]
          if artifact && goal_lc.match?(/\b(analy[sz]e|test|scan|report|generat|store|write|export)\b/)
            tasks << 'Carry out the requested analysis using the named skills and live evidence'
            tasks << "Write the requested report to #{artifact}"
            if goal_lc.match?(/\b(json|ya?ml|table|csv|tsv)\b/)
              fmt = goal_lc[/\b(json|ya?ml|table|csv|tsv)\b/]
              tasks << "Present the results in #{fmt} format"
            end
            return tasks
          end

          tasks << "Understand the request: #{truncate_goal(goal: goal_text)}"
          tasks << "Carry out the core work for: #{truncate_goal(goal: goal_text)}"

          if goal_lc.match?(/\b(json|ya?ml|table|csv|tsv)\b/)
            fmt = goal_lc[/\b(json|ya?ml|table|csv|tsv)\b/]
            tasks << "Present the results in #{fmt} format"
          elsif goal_lc.match?(/\b(display|show|print|output|format|present|report|export)\b/)
            tasks << 'Present the final results in the requested format'
          end

          # Only when the user actually asked about tests/lint — not bare "verify".
          tasks << 'Run specs, rubocop, and/or rake to verify' if goal_lc.match?(/\b(test|spec|rubocop|rake|lint)\b/) &&
                                                                  goal_lc.match?(%r{\b(/opt/pwn|code|patch|refactor|commit)\b})

          tasks
        rescue StandardError
          ["Carry out: #{truncate_goal(goal: opts[:goal])}"]
        end

        # Back-compat alias used by older call sites / specs.
        #
        # Supported Method Parameters::
        # tasks = PWN::AI::Agent::TaskSummarizer.heuristic_decompose(
        #   goal: 'required - user goal string'
        # )
        public_class_method def self.heuristic_decompose(opts = {})
          fallback_decompose(goal: opts[:goal])
        end

        private_class_method def self.truncate_goal(opts = {})
          # Task summaries are displayed in full — do not ellipsize goals or
          # plan items. (:len retained for call-site compatibility.)
          opts[:goal].to_s.gsub(/\s+/, ' ').strip
        end

        private_class_method def self.browse_shaped?(opts = {})
          Array(opts[:tools]).any? do |tool|
            next unless tool.is_a?(Hash)

            blob = "#{tool[:name]} #{tool[:args]}"
            blob.match?(/transparentbrowser|\.goto\b|browser_obj|dump_links|headless/i)
          end
        rescue StandardError
          false
        end

        # Infer a plain-English "why" from the tool mix.
        # When a plan is active the goal is already on the plan line — keep why short
        # so each about_to batch stays distinct and is not a near-duplicate of the plan.
        private_class_method def self.why_bit(opts = {})
          names = opts[:names]
          caps = capabilities_for(names: names)
          focus =
            if browse_shaped?(tools: opts[:tools])
              'navigate and collect from the live page'
            elsif caps.any? { |c| c.include?('shell') || c.include?('Ruby') }
              'gather evidence and apply code/host changes'
            elsif caps.any? { |c| c.include?('extro') || c.include?('verify') }
              'fact-check external state before acting'
            elsif caps.any? { |c| c.include?('memory') || c.include?('session') }
              'recall prior context relevant to the goal'
            elsif caps.any? { |c| c.include?('skill') }
              'consult or capture reusable procedure'
            elsif caps.any? { |c| c.include?('curriculum') || c.include?('score') }
              'score progress and tighten the feedback loop'
            else
              'advance the active plan item'
            end

          # Only attach the full goal when there is no plan line already shown.
          if opts[:with_goal]
            goal = opts[:request].to_s.gsub(/\s+/, ' ').strip
            return goal.empty? ? focus : "#{focus} toward: #{goal}"
          end
          focus
        rescue StandardError
          ''
        end

        # High-level brief for a collection of impending tool calls.
        # English tangible task is PRIMARY; tool counts/intents are secondary.
        # This string appears as name='task' and is shown in FULL in pwn-ai.
        #
        # Supported Method Parameters::
        # line = PWN::AI::Agent::TaskSummarizer.about_to(
        #   tools: 'optional - array of {name:, args:} or bare names',
        #   name: 'optional - single tool name (legacy one-tool path)',
        #   args: 'optional - single tool args (ignored for brief content)',
        #   request: 'optional - goal text',
        #   state: 'optional - fresh() hash'
        # )
        public_class_method def self.about_to(opts = {})
          state   = opts[:state]
          request = state && state[:request].to_s
          request = opts[:request].to_s if request.nil? || request.empty?

          tools = normalize_tools(tools: opts[:tools], name: opts[:name], args: opts[:args])
          names = tools.map { |t| t[:name] }
          # Ensure a plan exists so about_to can name the active task.
          plan(request: request, state: state) if state.is_a?(Hash) && Array(state[:plan]).empty? && !request.to_s.strip.empty?

          caps = capabilities_for(names: names)
          counts = tool_counts_phrase(names: names)
          intent = intent_phrase(tools: tools)

          via =
            if caps.empty?
              ''
            elsif intent != '' && counts != ''
              # Distinctive: tools + intent so shell/search ≠ shell/edit
              "via #{counts} (#{intent})"
            elsif counts != ''
              "via #{counts}"
            elsif caps.length == 1
              "via #{caps.first}"
            else
              head = caps[0..-2].join(', ')
              "via #{head}, and #{caps.last}"
            end

          # English task k/n is PRIMARY — same vocabulary as emit_plan!.
          # Previously tools led ("Next: shell×2 (search) [task k/n: …]") which
          # made mid-flight lines look like jargon and omitted the English task
          # on the first batch after the plan (operator "skipped tasks" complaint).
          plan_bit = ''
          has_plan = state.is_a?(Hash) && Array(state[:plan]).any?
          plan_emitted = state.is_a?(Hash) && state[:plan_emitted]
          if has_plan
            idx = active_plan_index(state: state)
            item = state[:plan][idx]
            if item
              state[:plan_idx] = idx if state.is_a?(Hash)
              plan_n = state[:plan].length
              # Always show English task k/n when a multi-step plan exists.
              # Single-task plans after emit_plan! already stated the only item —
              # keep via-only then to avoid a near-duplicate of the plan line.
              if plan_n <= 1 && plan_emitted
                plan_bit = ''
              else
                plan_bit = "task #{idx + 1}/#{plan_n}: #{item}"
              end
            end
          end

          # Goal lives on the emit_plan! line. Restate toward: only when this
          # brief would otherwise have no plan/goal linkage.
          why = why_bit(
            request: request,
            names: names,
            tools: tools,
            with_goal: plan_bit.empty? && !plan_emitted
          )

          # Compose: English task first, tools as via, optional why.
          line =
            if !plan_bit.empty? && !via.empty?
              "#{plan_bit} — #{via}"
            elsif !plan_bit.empty?
              plan_bit
            elsif !via.empty?
              "Next: #{via.sub(/\Avia /, '')}"
            else
              'Next: prepare the next step'
            end
          line = "#{line} — #{why}" unless why.empty?
          line = line.gsub(/[^\S\n]+/, ' ').strip
          # Full summary — never ellipsize. Pathological multi-MB blobs only
          # get a hard safety clamp far above normal executive briefs.
          line = line[0, 50_000] if line.length > 50_000

          # Suppress identical task lines when the model re-issues the same batch.
          if state.is_a?(Hash) && duplicate_brief?(state: state, line: line)
            state[:pending_tools] = names
            state[:emitted_for_batch] = true
            return nil
          end

          if state.is_a?(Hash)
            remember_brief!(state: state, line: line)
            state[:pending_tools] = names
            state[:emitted_for_batch] = true
          end
          line
        rescue StandardError
          'Next: advance the current goal'
        end

        # Active plain-English plan item (and index/n) for Loop / model steering.
        #
        # Supported Method Parameters::
        # info = PWN::AI::Agent::TaskSummarizer.active_task(
        #   state: 'required - fresh() hash'
        # )
        # => { idx:, n:, item:, label: "task k/n: …" } or nil
        public_class_method def self.active_task(opts = {})
          state = opts[:state]
          return nil unless state.is_a?(Hash)

          plan = Array(state[:plan])
          return nil if plan.empty?

          idx = active_plan_index(state: state)
          left = unfinished_tasks(state: state, messages: opts[:messages])
          idx = left.first[:idx] if left.any? && left.none? { |task| task[:idx] == idx }
          item = plan[idx].to_s
          return nil if item.empty?

          n = plan.length
          {
            idx: idx,
            n: n,
            item: item,
            label: "task #{idx + 1}/#{n}: #{item}"
          }
        rescue StandardError
          nil
        end

        # Remaining English work units that lack tool-result evidence.
        # Discover/map items need some tool evidence; implement/fix needs a
        # mutation signal; verify needs a spec/lint pass. Tool-count success
        # JSON is not enough — that was the premature-final / skipped-task bug.
        #
        # Supported Method Parameters::
        # left = PWN::AI::Agent::TaskSummarizer.unfinished_tasks(
        #   state: 'required - fresh() hash',
        #   messages: 'optional - Loop message array for extra coverage'
        # )
        # => [{ idx:, item:, label: }, ...]
        public_class_method def self.unfinished_tasks(opts = {})
          state = opts[:state]
          return [] unless state.is_a?(Hash)

          plan = Array(state[:plan]).map { |t| t.to_s.strip }
          return [] if plan.length < 2

          blob = coverage_blob(state: state, messages: opts[:messages])
          n = plan.length
          plan.each_with_index.filter_map do |item, i|
            next if item.empty? || item_covered?(item: item, blob: blob)

            { idx: i, item: item, label: "task #{i + 1}/#{n}: #{item}" }
          end
        rescue StandardError
          []
        end

        # True while a multi-step English plan still has uncovered work.
        # Loop uses this to refuse a text-only final.
        #
        # Supported Method Parameters::
        # open = PWN::AI::Agent::TaskSummarizer.plan_open?(
        #   state: 'required - fresh() hash',
        #   messages: 'optional - Loop message array'
        # )
        public_class_method def self.plan_open?(opts = {})
          unfinished_tasks(opts).any?
        rescue StandardError
          false
        end

        # Short block for engine messages: full plan + focus on active English task.
        # Primary steering surface so tools follow generated tasks, not only TUI.
        #
        # Supported Method Parameters::
        # text = PWN::AI::Agent::TaskSummarizer.plan_context(
        #   state: 'required - fresh() hash'
        # )
        public_class_method def self.plan_context(opts = {})
          state = opts[:state]
          return nil unless state.is_a?(Hash)

          plan = Array(state[:plan]).map { |t| t.to_s.strip }.reject(&:empty?)
          return nil if plan.empty?

          info = active_task(state: state)
          n = plan.length
          lines = []
          lines << '[pwn-ai/tasks] English tangible tasks are an advisory compass — the original request is the completion signal.'
          lines << 'Prefer CORE_TOOLS (shell, pwn_eval, memory, mistakes, learning) until that request is done or blocked.'
          lines << 'The task list is a breakdown, not a gate. Do not skip useful work; do not grind a covered item.'
          req_line = immutable_request_line(opts)
          lines << req_line if req_line
          lines << 'Original goal stays in context; the English tasks below are the work breakdown.'
          lines << "Active: #{info[:label]}" if info
          lines << "Tangible tasks (#{n}):"
          plan.each_with_index do |t, i|
            marker = info && i == info[:idx] ? '▶' : ' '
            lines << "  #{marker} task #{i + 1}/#{n}: #{t}"
          end
          lines.join("\n")
        rescue StandardError
          nil
        end

        # Build a Registry/tool-router relevance string from English tasks.
        # Prefer active task + full plan over the bare original request so
        # generated tangible tasks drive which tools are exposed/ranked.
        #
        # Supported Method Parameters::
        # q = PWN::AI::Agent::TaskSummarizer.relevance_query(
        #   state: 'optional - fresh() hash',
        #   request: 'optional - original user goal fallback'
        # )
        public_class_method def self.relevance_query(opts = {})
          state = opts[:state]
          request = opts[:request].to_s
          request = state[:request].to_s if request.empty? && state.is_a?(Hash)
          parts = []
          if state.is_a?(Hash)
            info = active_task(state: state)
            parts << info[:item] if info && !info[:item].to_s.empty?
            Array(state[:plan]).each { |t| parts << t.to_s }
          end
          parts << request unless request.empty?
          parts.map { |p| p.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?).uniq.join(' ')
        rescue StandardError
          opts[:request].to_s
        end

        # Inject / refresh the active-task focus into Loop messages when plan_idx changes.
        # Returns the message content when a new injection is needed, else nil.
        #
        # Supported Method Parameters::
        # text = PWN::AI::Agent::TaskSummarizer.active_task_prompt(
        #   state: 'required - fresh() hash',
        #   force: 'optional - Boolean re-emit even if idx unchanged'
        # )
        public_class_method def self.active_task_prompt(opts = {})
          state = opts[:state]
          return nil unless state.is_a?(Hash)
          return nil unless plan_open?(state: state, messages: opts[:messages])

          info = active_task(state: state, messages: opts[:messages])
          return nil unless info

          force = !opts[:force].nil?
          prev = state[:focus_injected_idx]
          return nil if !force && !prev.nil? && prev.to_i == info[:idx].to_i

          state[:focus_injected_idx] = info[:idx]
          # First injection after plan: full plan_context. Later: compact focus.
          if prev.nil? || force
            plan_context(state: state, request: opts[:request])
          else
            done_bit =
              if state[:last_advanced_from]
                from = state[:last_advanced_from].to_i
                prev_item = Array(state[:plan])[from]
                prev_item ? "Completed task #{from + 1}. " : ''
              else
                ''
              end
            focus = "#{done_bit}[pwn-ai/tasks] Compass: #{info[:label]}. " \
                    'Finish the original request with CORE_TOOLS; this task list is advisory.'
            req_line = immutable_request_line(opts)
            req_line ? "#{focus} #{req_line}" : focus
          end
        rescue StandardError
          nil
        end

        # Pull the operator's original ask out of curriculum / critic / GOAL+PLAN
        # wrappers so planning and model-facing prompts never treat a PLAN:
        # tool-call scaffold as the user request.
        #
        # Supported Method Parameters::
        # text = PWN::AI::Agent::TaskSummarizer.canonical_request(
        #   request: 'required - raw user or wrapper string'
        # )
        public_class_method def self.canonical_request(opts = {})
          text = opts[:request].to_s
          return '' if text.strip.empty?

          body = text.sub(/\A\s*REQUEST:\s*/i, '')
          if (m = body.match(/\AGOAL:\s*(.+?)(?=(?:\n\s*|\s+)(?:PLAN|ANSWER|FLAW|PATCH)\s*:|\z)/mi))
            extracted = squeeze_request_ws(text: m[1])
            return extracted unless extracted.empty?
          end
          if (idx = body =~ /\n\s*PLAN\s*:\s*(?:\n|\z)/i)
            head = squeeze_request_ws(text: body[0...idx])
            return head unless head.empty?
          end
          if (m = body.match(/\A(.+?)\s+PLAN\s*:\s*\d+[.):]/i))
            head = squeeze_request_ws(text: m[1])
            return head unless head.empty?
          end

          squeeze_request_ws(text: body)
        rescue StandardError
          opts[:request].to_s.gsub(/\s+/, ' ').strip
        end

        private_class_method def self.squeeze_request_ws(opts = {})
          opts[:text].to_s.gsub(/\s+/, ' ').strip
        end

        private_class_method def self.plan_scaffold_item?(opts = {})
          s = opts[:item].to_s.gsub(/\s+/, ' ').strip
          return true if s.empty?
          return true if s.match?(/\A(?:GOAL|PLAN|REQUEST|ANSWER|FLAW|PATCH)\s*:/i)
          return true if s.match?(/\A\w+\s+command\s*=/i)

          false
        rescue StandardError
          false
        end

        private_class_method def self.reject_scaffold_tasks(opts = {})
          Array(opts[:tasks]).map { |t| t.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?).reject do |item|
            plan_scaffold_item?(item: item) || tool_jargon_task?(item: item)
          end
        rescue StandardError
          []
        end

        # Resolve the original user request for model-facing task prompts.
        # Prefer an explicit opts[:request] override, else the pinned
        # state[:original_request], else state[:request]. Wrappers are stripped.
        private_class_method def self.immutable_request_line(opts = {})
          state = opts[:state]
          request = opts[:request].to_s.strip
          request = canonical_request(request: request) unless request.empty?
          if request.empty? && state.is_a?(Hash)
            request = state[:original_request].to_s.strip
            request = state[:request].to_s.strip if request.empty?
            request = canonical_request(request: request) unless request.empty?
          end
          return nil if request.empty?

          "Original request (immutable): #{request}"
        end

        private_class_method def self.active_plan_index(opts = {})
          state = opts[:state]
          plan = Array(state[:plan])
          return 0 if plan.empty?

          # Prefer explicit plan_idx whenever present (emit_plan! seeds 0;
          # maybe_advance_plan! walks forward). Do not bypass idx==0 with
          # total-based buckets — that skipped early plain-English steps.
          return state[:plan_idx].to_i.clamp(0, plan.length - 1) if state.key?(:plan_idx)

          total = state[:total].to_i
          return 0 if total <= 0

          n = plan.length
          return 0 if n <= 1

          per = [3, 4].max
          bucket = (total / per.to_f).floor
          [bucket, n - 1].min
        rescue StandardError
          0
        end

        # ----------------------------------------------------------------
        # RL-adjacent executive hooks (index/rewrite only - no credit/ORM).
        # Credit assignment stays in Reward/Metrics; Learning only tags.
        # ----------------------------------------------------------------

        # Roots of registered agent tools — used to detect plan_first outlines
        # that list tool calls instead of plain-English tangible work.
        TOOL_NAME_ROOTS = %w[
          shell pwn_eval
          memory sessions mistakes learning extro skill agent swarm cron
          reward curriculum metrics
        ].freeze

        # True when a candidate plan item is tool jargon (e.g. "`shell`",
        # "shell / pwn_eval", "pwn_eval ×1") rather than a plain-English task.
        # plan_first asks for "exact tool calls"; those must NOT replace the
        # operator-facing English tangible task list.
        #
        # Supported Method Parameters::
        # yes = PWN::AI::Agent::TaskSummarizer.tool_jargon_task?(
        #   item: 'required - candidate task string'
        # )
        public_class_method def self.tool_jargon_task?(opts = {})
          s = opts[:item].to_s.gsub(/\s+/, ' ').strip
          return false if s.empty?

          # Bare / backticked tool token(s), optional ×N counts, slashes.
          # e.g. "`shell`", "shell", "shell / pwn_eval", "pwn_eval ×1"
          if s.match?(%r{\A(?:`?[a-z][a-z0-9_]*`?(?:\s*[×xX]\s*\d+)?(?:\s*(?:/|,|→|->)\s*`?[a-z][a-z0-9_]*`?(?:\s*[×xX]\s*\d+)?)*)\z})
            token = s.downcase.gsub(%r{[`×x\d\s,→/>-]}, ' ').split.first.to_s
            return true if TOOL_NAME_ROOTS.include?(token) ||
                           TOOL_NAME_ROOTS.any? { |r| token.start_with?("#{r}_") }
          end

          # Leading tool name then args: "shell - rg foo", "pwn_eval: code"
          first = s.split(/[\s:—-]+/).first.to_s.downcase.gsub('`', '')
          return true if TOOL_NAME_ROOTS.include?(first) ||
                         TOOL_NAME_ROOTS.any? { |r| first.start_with?("#{r}_") }

          tokens = s.scan(/[A-Za-z][A-Za-z0-9_]{2,}/)
          return false if tokens.length > 8 # prose sentences stay English

          toolish = tokens.count do |t|
            tl = t.downcase
            TOOL_NAME_ROOTS.include?(tl) ||
              TOOL_NAME_ROOTS.any? { |r| tl.start_with?("#{r}_") }
          end
          # Majority tool tokens on a short line ⇒ jargon
          toolish.positive? && toolish >= (tokens.length + 1) / 2 && tokens.length <= 6
        rescue StandardError
          false
        end

        # Parse a plan_first / red_team surviving outline into tangible tasks.
        # Numbered lines ("1. foo", "2) bar") preferred; bullet lines fallback.
        #
        # Supported Method Parameters::
        # tasks = PWN::AI::Agent::TaskSummarizer.parse_outline_tasks(
        #   outline: 'required - free-text plan outline'
        # )
        public_class_method def self.parse_outline_tasks(opts = {})
          text = opts[:outline].to_s
          return [] if text.strip.empty?

          tasks = []
          text.split(/\n+/).each do |ln|
            ln = ln.strip
            next if ln.empty?
            next if ln.match?(/\Ap\s*\(\s*success\s*\)\s*=/i)
            next if ln.match?(/\Aconfidence\s*=/i)
            next if ln.match?(/\APLAN:\s*\z/i)

            next unless (m = ln.match(/\A(?:\d+[.):]|[-*•])\s+(.+)\z/))

            item = m[1].to_s.strip
            # Strip trailing tool-arg noise common in plan_first
            item = item.sub(/\s+[—-]\s+.*\z/, '').strip
            tasks << item unless item.empty?
          end
          if tasks.length < MIN_PLAN_TASKS
            inline = text.scan(/(?:^|\s)\d+[.):]\s+([^\d]+?)(?=(?:\s+\d+[.):]\s+)|$)/)
            tasks = inline.flatten.map { |t| t.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?) if inline.length >= MIN_PLAN_TASKS
          end
          tasks = tasks.map { |t| t.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?).uniq
          tasks.first(MAX_PLAN_TASKS)
        rescue StandardError
          []
        end

        # After S4 red_team / plan_first: optionally rewrite ts_state[:plan]
        # from the surviving outline so the task line and adversarial plan
        # are one object. Does not re-emit the plan line (TUI already showed
        # the submit-time breakdown); later about_to batches use the unified idx.
        # REFUSES tool-jargon outlines from plan_first ("exact tool calls") so
        # English tangible tasks stay the sole operator + model vocabulary.
        #
        # Supported Method Parameters::
        # plan = PWN::AI::Agent::TaskSummarizer.unify_plan!(
        #   state: 'required - fresh() hash',
        #   outline: 'required - plan_first text and/or red_team hint',
        #   source: 'optional - :plan_first|:red_team|:merged (default :merged)'
        # )
        public_class_method def self.unify_plan!(opts = {})
          state = opts[:state]
          return nil unless state.is_a?(Hash)

          outline = opts[:outline].to_s
          return Array(state[:plan]) if outline.strip.empty?

          tasks = parse_outline_tasks(outline: outline)
          return Array(state[:plan]) if tasks.length < MIN_PLAN_TASKS

          # plan_first prompts for "exact tool calls (name + key args)". Those
          # outlines must NOT clobber the English tangible plan from plan() /
          # emit_plan!. Operator TUI (plan_text) and model steering
          # (plan_context / about_to / active_task) must share one English list.
          jargon_n = tasks.count { |t| tool_jargon_task?(item: t) }
          if jargon_n >= (tasks.length + 1) / 2
            state[:unified_from] = outline.to_s[0, 500]
            state[:plan_source] = :kept_english if Array(state[:plan]).any?
            return Array(state[:plan])
          end

          # Drop any residual tool-jargon lines mixed into an English outline.
          tasks = tasks.reject { |t| tool_jargon_task?(item: t) }
          return Array(state[:plan]) if tasks.length < MIN_PLAN_TASKS

          # Keep a verify/close step when outline omitted one.
          tasks = normalize_task_list(tasks: tasks, goal: state[:request].to_s)
          prev_idx = state[:plan_idx].to_i
          state[:plan] = tasks
          state[:plan_source] = (opts[:source] || :merged).to_sym
          state[:unified_from] = outline.to_s[0, 500]
          # Preserve relative progress when possible; clamp into new length.
          state[:plan_idx] = prev_idx.clamp(0, [tasks.length - 1, 0].max)
          # Keep both UI surfaces in sync: refresh plan_text so the TUI
          # "Tangible tasks" block matches plan_context / about_to vocabulary.
          state[:plan_text] = format_plan(tasks: tasks, request: state[:request].to_s) if state[:plan_emitted] || state[:plan_text]
          tasks
        rescue StandardError
          Array(opts[:state].is_a?(Hash) ? opts[:state][:plan] : nil)
        end

        # Advance or hold plan_idx from an R2 step batch.
        # Advance ONLY when the current English task has completion evidence
        # (mutate/verify) or the batch clearly hands off to the NEXT task's
        # phase. A +1 search streak is telemetry — never task completion.
        # Any -1 or mistake fingerprint on the batch -> do not advance.
        #
        # Supported Method Parameters::
        # idx = PWN::AI::Agent::TaskSummarizer.apply_prm_advancement!(
        #   state: 'required - fresh() hash',
        #   rewards: 'required - Array of -1|0|1 (batch order)',
        #   intents: 'optional - Array of intent verb strings for the batch',
        #   names: 'optional - tool names in the batch',
        #   result: 'optional - latest tool result string',
        #   mistake: 'optional - truthy when a mistake fingerprint hit this batch'
        # )
        public_class_method def self.apply_prm_advancement!(opts = {})
          state = opts[:state]
          return nil unless state.is_a?(Hash)

          plan = Array(state[:plan])
          return state[:plan_idx].to_i if plan.length <= 1

          idx = state[:plan_idx].to_i
          return idx if idx >= plan.length - 1

          rewards = Array(opts[:rewards]).map(&:to_i)
          return idx if rewards.empty?

          # Hold on any regression or explicit mistake fingerprint.
          if opts[:mistake] || rewards.any?(&:negative?)
            state[:prm_pos_streak] = 0
            state[:last_prm_signal] = :hold_regress
            return idx
          end

          pos = rewards.count(&:positive?)
          if pos.zero?
            state[:prm_pos_streak] = 0
            state[:last_prm_signal] = :hold_neutral
            return idx
          end

          # Streak is telemetry only — never an advance trigger.
          state[:prm_pos_streak] = state[:prm_pos_streak].to_i + pos

          item = plan[idx].to_s
          intents = Array(opts[:intents]).map { |iv| iv.to_s.downcase }.reject(&:empty?)
          names = Array(opts[:names]).map(&:to_s)
          intent_s = (intents + names).join(' ')

          if task_complete_enough?(
            item: item,
            result: opts[:result],
            names: names,
            intents: intents,
            state: state
          )
            return bump_plan!(state: state, idx: idx, signal: :advance_complete)
          end

          nxt = plan[idx + 1].to_s
          return bump_plan!(state: state, idx: idx, signal: :advance_handoff) if handoff_to_next?(state: state, item: item, next_item: nxt, intent: intent_s)

          state[:last_prm_signal] = :hold_open
          idx
        rescue StandardError
          opts[:state].is_a?(Hash) ? opts[:state][:plan_idx].to_i : 0
        end

        MUTATION_DONE_RX = /
          patched|wrote\s|file\.write|fileutils|sed\s+-i|binwrite|
          syntax\sok|changed\s+\d+\s+lines
        /ix
        VERIFY_DONE_RX = /
          0\s+offenses|0\s+failures|examples?,\s*0|
          all\s+examples?\s+passed|\d+\s+runs?,\s*0\s+failures
        /ix
        # Ran the verifier — green or red. "4 offenses" still completes the
        # verify English task; remaining defects belong to implement/fix.
        VERIFY_RAN_RX = /
          \d+\s+offenses?|\d+\s+failures|examples?,\s*\d+|
          finished\s+in\s+\d|\d+\s+runs?,\s*\d+\s+failures
        /ix
        HANDOFF_MIN_TOOLS = 2
        DISCOVER_MIN_TOOLS = 3

        private_class_method def self.task_phase(opts = {})
          s = opts[:item].to_s.downcase
          # Strict test/lint verify first — stems must not sit inside \b...\b
          # ("\bverif\b" never matches "verify"; that was the stuck-plan bug).
          return :verify if s.match?(
            /\b(rspec|rubocop|rake|lint|end-to-end)\b|run spec|run test|confirm the final/
          )
          return :present if s.match?(/\bpresent\b|\breport completion\b|\breport results\b/)
          # Soft "verify the result and report" is a closer, not a test runner.
          return :present if s.match?(/\bverif\w*\b/) && !s.match?(/\b(rspec|rubocop|rake|lint|spec|test)\b/)
          return :mutate if s.match?(
            /\b(implement\w*|fix|patch\w*|chang\w*|improv\w*|write|apply|wire|refactor\w*)\b/
          )
          return :discover if s.match?(
            /\b(locat\w*|find|read|inspect|recon\w*|understand|decompos\w*|map|identif\w*|gather|discover|enumerat\w*|scan|probe|determin\w*|root cause|where and why|track|navigat\w*|browse|goto)\b/
          )

          :generic
        rescue StandardError
          :generic
        end

        private_class_method def self.intent_phase(opts = {})
          s = opts[:intent].to_s.downcase
          return :verify if s.match?(/test|rubocop|rake|rspec|offenses|failures/)
          return :mutate if s.match?(/edit|mutate|write|patch|sed\s+-i|file.write|refactor/)
          return :discover if s.match?(/search|read|recon|extro|sessions|memory|find|list|scan|inspect|locat|browse|goto|navigat/)

          :generic
        rescue StandardError
          :generic
        end

        # Exclusive phase match. A search tool must not "match" an implement
        # task, and "plans" in an English item must not count as discovery.
        # :present closers accept any non-empty intent (the work already ran).
        private_class_method def self.task_intent_match?(opts = {})
          item = opts[:item].to_s.downcase
          intent = opts[:intent].to_s.downcase
          return false if item.empty? || intent.empty?

          phase = task_phase(item: item)
          return true if phase == :present

          ip = intent_phase(intent: intent)
          return false if ip == :generic && phase != :generic

          phase == ip || phase == :generic
        rescue StandardError
          false
        end

        private_class_method def self.coverage_blob(opts = {})
          state = opts[:state]
          parts = []
          parts << state[:evidence_blob].to_s if state.is_a?(Hash)
          Array(opts[:messages]).each do |msg|
            next unless msg.is_a?(Hash)

            role = msg[:role].to_s
            if role == 'tool'
              parts << msg[:name].to_s
              parts << msg[:content].to_s[0, 2_000]
            elsif role == 'assistant'
              Array(msg[:tool_calls]).each do |tc|
                parts << tc.dig(:function, :name).to_s
                parts << tc.dig(:function, :arguments).to_s[0, 1_000]
              end
            end
          end
          parts.join("\n").downcase
        rescue StandardError
          ''
        end

        private_class_method def self.item_covered?(opts = {})
          item = opts[:item].to_s
          blob = opts[:blob].to_s.downcase
          phase = task_phase(item: item)
          case phase
          when :mutate
            blob.match?(MUTATION_DONE_RX)
          when :verify
            blob.match?(VERIFY_DONE_RX) || blob.match?(VERIFY_RAN_RX)
          else
            # discover / present / generic: some real tool evidence, not empty / tiny JSON
            blob.strip.length >= 40
          end
        rescue StandardError
          false
        end

        private_class_method def self.task_complete_enough?(opts = {})
          phase = task_phase(item: opts[:item])
          blob = [
            opts[:result],
            Array(opts[:names]).join(' '),
            Array(opts[:intents]).join(' ')
          ]
          blob << opts[:state][:evidence_blob] if opts[:state].is_a?(Hash)
          joined = blob.join(' ')

          case phase
          when :mutate, :verify
            item_covered?(item: opts[:item], blob: joined)
          when :discover, :generic, :present
            browse_hit = joined.match?(/effect["\s:=]+browse|transparentbrowser|\.goto\b|\bbrowse\b/i)
            min_tools = browse_hit ? 1 : DISCOVER_MIN_TOOLS
            on_task = opts[:state].is_a?(Hash) ? opts[:state][:tools_on_task].to_i : 0
            return false if on_task < min_tools
            return false unless item_covered?(item: opts[:item], blob: joined)

            intent_s = (Array(opts[:intents]) + Array(opts[:names])).join(' ')
            task_intent_match?(item: opts[:item], intent: intent_s) || phase == :present || browse_hit
          else
            false
          end
        rescue StandardError
          false
        end

        private_class_method def self.handoff_to_next?(opts = {})
          nxt = opts[:next_item].to_s
          return false if nxt.strip.empty?

          on_task = opts[:state].is_a?(Hash) ? opts[:state][:tools_on_task].to_i : 0
          return false if on_task < HANDOFF_MIN_TOOLS

          cur_p = task_phase(item: opts[:item])
          nxt_p = task_phase(item: nxt)
          return false if nxt_p == :generic
          return false if cur_p == nxt_p
          return false unless task_intent_match?(item: nxt, intent: opts[:intent]) || nxt_p == :present

          true
        rescue StandardError
          false
        end

        private_class_method def self.bump_plan!(opts = {})
          state = opts[:state]
          idx = opts[:idx].to_i
          state[:last_advanced_from] = idx
          state[:plan_idx] = idx + 1
          state[:prm_pos_streak] = 0
          state[:tools_on_task] = 0
          state[:last_prm_signal] = opts[:signal] || :advance
          idx + 1
        end

        # Nudge plan_idx forward only on a real next-task phase handoff.
        # Never advance because "enough tools landed" — that skipped English work.
        private_class_method def self.maybe_advance_plan!(opts = {})
          state = opts[:state]
          return unless state.is_a?(Hash)

          plan = Array(state[:plan])
          return if plan.length <= 1

          idx = state[:plan_idx].to_i
          return if idx >= plan.length - 1

          names = Array(opts[:names])
          intent_s = "#{opts[:intent]} #{names.join(' ')}"
          return unless handoff_to_next?(
            state: state,
            item: plan[idx].to_s,
            next_item: plan[idx + 1].to_s,
            intent: intent_s
          )

          bump_plan!(state: state, idx: idx, signal: :advance_phase)
        rescue StandardError
          nil
        end

        private_class_method def self.normalize_tools(opts = {})
          list = Array(opts[:tools])
          name = opts[:name]
          args = opts[:args]
          list = [{ name: name, args: args }] if list.empty? && !name.nil?
          normalized = list.map do |tool|
            case tool
            when Hash
              {
                name: (tool[:name] || tool['name']).to_s,
                args: tool[:args] || tool['args']
              }
            else
              { name: tool.to_s, args: nil }
            end
          end
          normalized.reject { |tool| tool[:name].empty? }
        rescue StandardError
          []
        end

        # Plain-English advancement line after plan_idx moves forward.
        # Same "task k/n:" vocabulary as emit_plan! / about_to.
        private_class_method def self.advancement_brief(opts = {})
          state = opts[:state]
          return nil unless state.is_a?(Hash)

          plan = Array(state[:plan])
          return nil if plan.empty?

          from_idx = opts[:from_idx]
          from_idx = state[:last_advanced_from].to_i if from_idx.nil?
          to_idx = state[:plan_idx].to_i.clamp(0, plan.length - 1)
          n = plan.length
          done = plan[from_idx].to_s if from_idx && from_idx >= 0 && from_idx < n
          nxt = plan[to_idx].to_s
          parts = []
          parts << "Advanced past task #{from_idx + 1}/#{n}: #{done}" if done && !done.empty?
          parts << "now task #{to_idx + 1}/#{n}: #{nxt}" if nxt && !nxt.empty?
          return nil if parts.empty?

          line = parts.join(' — ')
          # Dedup against last brief so rapid double-advance does not spam.
          return nil if duplicate_brief?(state: state, line: line)

          remember_brief!(state: state, line: line)
          state[:since_emit] = 0
          state[:last_emit_at] = Time.now
          line
        rescue StandardError
          nil
        end

        # Kept for debug/verbose only — never the primary task UX.
        private_class_method def self.arg_snippet(opts = {})
          return '' unless verbose?

          args = opts[:args]
          s = case args
              when String
                args
              when Hash
                prefer = %w[command code query claim url request path file text prompt ruby script id name task]
                hit = prefer.map { |k| args[k] || args[k.to_sym] }.compact.first
                hit ? hit.to_s : args.inspect
              else
                args.inspect
              end
          s = s.to_s.gsub(/\s+/, ' ').strip
          return '' if s.empty?

          s.length > 100 ? "#{s[0, 100]}…" : s
        rescue StandardError
          ''
        end

        # Record a completed tool. Does NOT emit task lines with results.
        # Returns a deferred progress brief only when every_n / interval
        # fires AND verbose? is on; otherwise nil (silent coalesce).
        #
        # Supported Method Parameters::
        # line = PWN::AI::Agent::TaskSummarizer.record!(
        #   state: 'required - fresh() hash',
        #   name: 'required - tool name',
        #   args: 'optional - tool args',
        #   result: 'optional - tool result string'
        # )
        public_class_method def self.record!(opts = {})
          state = opts[:state]
          name = opts[:name]
          args = opts[:args]
          result = opts[:result]
          return nil unless state

          preview = verbose? ? arg_snippet(args: args).to_s[0, 60] : ''
          rs = result.to_s
          ok = !rs.match?(/\A\s*\{?\s*"?(success|ok)"?\s*=>\s*false/i) &&
               !rs.match?(/ERROR:|Traceback|NoMethodError|StandardError/i)
          state[:events] << { name: name.to_s, preview: preview, ok: ok, t: Time.now }
          state[:events].shift while state[:events].size > MAX_BUFFER
          state[:counts][name.to_s] += 1
          state[:total] += 1
          state[:since_emit] += 1
          state[:tools_on_task] = state[:tools_on_task].to_i + 1
          state[:emitted_for_batch] = false
          chunk = "#{name} #{preview} #{rs.to_s[0, 800]}"
          state[:evidence_blob] = "#{state[:evidence_blob]} #{chunk}"
          state[:evidence_blob] = state[:evidence_blob][-16_000..] if state[:evidence_blob].to_s.length > 20_000
          intent = intent_phrase(tools: [{ name: name.to_s, args: args }])
          # Live R2-local signal from tool outcome (executive idx only).
          # Full ORM/PRM credit stays in Reward during auto_introspect.
          local_r =
            if ok then 1
            elsif rs.match?(/exit["\s:=]+1\b/i) && name.to_s == 'shell' then 0
            else -1
            end
          mistake_hit = rs.match?(%r{REPEATED FAILURE|KNOWN FIX|\[pwn-ai/mistakes\]}i)
          prev_idx = state[:plan_idx].to_i
          apply_prm_advancement!(
            state: state,
            rewards: [local_r],
            intents: [intent],
            names: [name.to_s],
            result: rs,
            mistake: mistake_hit
          )
          # Heuristic phase-shift remains as a backstop when PRM streak has not fired.
          if state[:last_prm_signal].to_s.start_with?('advance')
            # already moved this record
          else
            maybe_advance_plan!(
              state: state,
              names: [name.to_s],
              intent: intent
            )
          end

          # Clearer advancement UX: when plan_idx moves, emit English task k/n brief
          # so operators see the same vocabulary as emit_plan! / about_to.
          if state[:plan_idx].to_i > prev_idx
            brief = advancement_brief(state: state, from_idx: prev_idx)
            state[:last_advance_brief] = brief
            return brief if brief
          end

          # Default: no mid-flight task spam. Progress lines only when verbose.
          return nil unless verbose?

          due = state[:since_emit] >= every_n ||
                (Time.now - state[:last_emit_at]) >= interval_s
          due ? emit!(state: state) : nil
        end

        # Optional progress / done line (verbose or flush). Still plain English;
        # never includes raw tool results. Shown in full (no 60-char goal cut).
        #
        # Supported Method Parameters::
        # line = PWN::AI::Agent::TaskSummarizer.emit!(
        #   state: 'required - fresh() hash',
        #   final: 'optional - Boolean closing brief (default: false)'
        # )
        public_class_method def self.emit!(opts = {})
          state = opts[:state]
          final = opts[:final]
          return nil if state.nil? || state[:events].empty?

          counts = state[:counts].sort_by { |_, c| -c }.map { |n, c| "#{n}×#{c}" }
          recent = state[:events].last([every_n, 1].max)
          caps = capabilities_for(names: recent.map { |e| e[:name] })
          focus =
            if caps.empty?
              'work'
            elsif caps.length == 1
              caps.first
            else
              "#{caps[0..-2].join(', ')}, and #{caps.last}"
            end
          fails = state[:events].count { |e| !e[:ok] }
          fail_bit = fails.positive? ? " (#{fails} hit issues)" : ''
          phase = final ? 'Finished' : 'Progress'
          goal = state[:request].to_s.gsub(/\s+/, ' ').strip
          goal_bit =
            if goal.empty?
              ''
            else
              # Full goal — no 60-char ellipsis.
              " toward: #{goal}"
            end
          plan_bit = ''
          if Array(state[:plan]).any?
            info = active_task(state: state)
            plan_bit =
              if info
                " | #{info[:label]}"
              else
                " | plan: #{state[:plan].length} tangible tasks"
              end
          end
          state[:since_emit] = 0
          state[:last_emit_at] = Time.now
          "#{phase}: #{focus} — #{state[:total]} tool calls so far (#{counts.first(6).join(', ')})#{fail_bit}#{goal_bit}#{plan_bit}"
        end

        # Supported Method Parameters::
        # line = PWN::AI::Agent::TaskSummarizer.flush!(
        #   state: 'required - fresh() hash'
        # )
        public_class_method def self.flush!(opts = {})
          emit!(state: opts[:state], final: true)
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              state = PWN::AI::Agent::TaskSummarizer.fresh(request: 'ship task briefs to execs')
              plan = PWN::AI::Agent::TaskSummarizer.plan(request: state[:request], state: state)
              text = PWN::AI::Agent::TaskSummarizer.emit_plan!(state: state)
              # → "Goal: ...\nTangible tasks (N) — each may use many tools:\n  task 1/N: ...\n  task 2/N: ..."
              # UI: on_tool.call('task', text, '')  # full text, no truncation
              # One task brief for a whole tool collection (one-to-many):
              pre = PWN::AI::Agent::TaskSummarizer.about_to(
                tools: [{ name: 'shell' }, { name: 'pwn_eval' }],
                state: state
              )
              # → "task k/N: <english> — via shell, pwn_eval (search+eval-ruby)"
              ctx = PWN::AI::Agent::TaskSummarizer.plan_context(state: state)
              focus = PWN::AI::Agent::TaskSummarizer.active_task_prompt(state: state)
              # then real tools print on their own lines; record! stays silent by default
              PWN::AI::Agent::TaskSummarizer.record!(
                state: state,
                name: 'shell',
                args: 'ls',
                result: '{success:true}'
              )
              line = PWN::AI::Agent::TaskSummarizer.flush!(state: state)  # optional closing brief
              PWN::AI::Agent::TaskSummarizer.enabled?
              PWN::AI::Agent::TaskSummarizer.verbose?
              PWN::AI::Agent::TaskSummarizer.llm_plan_enabled?
              PWN::AI::Agent::TaskSummarizer.unify_plan!(state: state, outline: plan_text)
              PWN::AI::Agent::TaskSummarizer.tool_jargon_task?(item: '`shell`')
              PWN::AI::Agent::TaskSummarizer.relevance_query(state: state, request: state[:request])
              PWN::AI::Agent::TaskSummarizer.apply_prm_advancement!(state: state, rewards: [1, 1], intents: ['search'])
              PWN::AI::Agent::TaskSummarizer.parse_outline_tasks(outline: plan_text)
              PWN::AI::Agent::TaskSummarizer.every_n
              PWN::AI::Agent::TaskSummarizer.interval_s

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
