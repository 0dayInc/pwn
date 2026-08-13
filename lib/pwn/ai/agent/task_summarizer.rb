# frozen_string_literal: true

require 'json'

module PWN
  module AI
    module Agent
      # High-level executive brief of the work the agent is about to do.
      #
      # Request kind (statement | question | autonomous_goal) gates planning:
      #   - general statements and questions -> NO multi-step task breakdown
      #   - autonomous goals -> MUST decompose into ordered tangible work units
      #     (each unit may use one or more tools)
      #
      # English tangible tasks are PRIMARY (not tool jargon):
      #   1. plan(request:) — on user submit, break the goal into an ordered
      #      list of plain-English tasks via the active LLM (each task is a
      #      coherent unit that may require many tool calls). ONLY autonomous goals (not bare statements/questions).
      #      Works for any — no static per-domain task lists.
      #   2. about_to(tools:) — per tool-batch brief led by the active
      #      "task k/n: <english>" item (same vocabulary as emit_plan!).
      #      Tool counts/intents are a secondary "via …" suffix only.
      #   3. active_task_prompt / plan_context — injected into Loop messages
      #      so generated tasks steer tool choice, not only the TUI.
      #   4. record! emits an advancement brief when plan_idx moves forward.
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
          You are the pwn-ai Task Planner for AUTONOMOUS GOALS only.
          The caller already classified this request as work the agent must
          accomplish (not a bare statement or a question). Break it into an
          ordered list of tangible work units. Rules:
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
          req = opts[:request].to_s
          {
            request: req,
            request_kind: opts[:request_kind] || request_kind(request: req),
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
            tools_on_task: 0
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
                when /\b(write|file\.|fileutils|open\(|binwrite|puts )\b/ then 'mutate-ruby'
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

        # ------------------------------------------------------------------
        # Top-level request kind (statement | question | autonomous_goal).
        # General statements and questions must NOT be multi-step planned.
        # Autonomous goals MUST decompose into ordered tangible work units.
        #
        # Classification priority:
        #   1. Injected kind / llm_kind (tests)
        #   2. Cheap deterministic intent (greeting/howto/recall/recon)
        #   3. LLM classify when request_kind_llm/task_summary_llm is on
        #   4. Regex / structure heuristics (offline fallback)
        #
        # Supported Method Parameters::
        # kind = PWN::AI::Agent::TaskSummarizer.request_kind(
        #   request: 'required - user text',
        #   kind: 'optional - precomputed symbol',
        #   llm_kind: 'optional - injected LLM label (tests)',
        #   heuristic_only: 'optional - skip LLM (Boolean)'
        # )
        # ------------------------------------------------------------------
        KIND_LABELS = %i[statement question autonomous_goal].freeze

        # Review / opinion asks are questions unless the user also asks to implement.
        OPINION_REVIEW_RX = /
          \b(?:
            suggest\s+(?:areas?|ways?|ideas?)|
            areas?\s+for\s+improvement|
            what\s+(?:do\s+you\s+think|would\s+you\s+(?:change|improve))|
            your\s+(?:take|opinion|assessment|review)\b|
            briefly\s+describe|
            review\s+(?:the|this|our)
          )
        /ix

        IMPLEMENT_RX = /
          \b(?:implement|fix\s+all|apply|patch|land|ship)\b
        /ix

        STATEMENT_RX = /
          \A\s*(
            (?:fyi|note|noted|heads\s*up|for\s+the\s+record|just\s+so\s+you\s+know)\b |
            (?:i\s+(?:think|believe|notice|see|observed)|looks\s+like)\b |
            (?:the|this|that)\s+(?:\w+\s+){0,6}(?:is|are|was|were|seems|looks)\b
          )
        /ix

        # Interrogative openers / trailing ? / how-to phrases.
        # Also match mid-line "what/why/..." after a short preface
        # ("excellent - what is my hostname?").
        # Do NOT treat bare "Do three things..." as a question (imperative goal).
        QUESTION_RX = /
          \A\s*(?:
            (?:what|why|when|where|who|whom|whose|which|how)\b
            |
            (?:is|are|was|were|do|does|did|can|could|would|should|may|might|will)\s+
            (?:i|you|we|they|he|she|it|this|that|there|the|a|an|my|your|our|any|
               anyone|someone|everyone|something|anything|everything)\b
          )
          |
          (?:\A|\.\s+|[-–—:]\s+|\b)(?:what|why|when|where|who|whom|whose|which|how)\b
          |
          \?\s*\z
          |
          \b(?:how\s+to|how\s+do\s+i|how\s+can\s+i|explain\s+how|usage\s+of|syntax\s+for)\b
        /ix

        # Strong "agent, do this" signals — avoid bare nouns like "build"/"scan"
        # inside ordinary prose ("the build is green", "ping scan flags").
        AUTONOMOUS_GOAL_RX = /
          \b(?:
            (?:please\s+)(?:\w+\s+){0,4}(?:implement|fix|patch|refactor|rewrite|migrate|
              deploy|install|compile|commit|push|create|remove|delete|update|change|edit|
              write|run|execute|scan|probe|enumerate|discover|find|locate|audit|harden|
              resolve|debug|diagnose|investigate|optimize|configure|enable|disable|
              start|stop|restart|ship|finish|complete|make|ensure|verify)
            |
            (?:can|could|would)\s+you\s+(?:please\s+)?(?:\w+\s+){0,3}(?:do|run|fix|
              implement|scan|find|make|update|change|write|patch|refactor|add|remove|
              create|locate|resolve|debug|ship|finish)
            |
            \bi\s+need\s+you\s+to\b |
            \byour\s+job\s+is\s+to\b |
            \bgo\s+ahead\b |
            \bdo\s+it\b |
            \bship\s+it\b |
            \bmake\s+it\s+so\b |
            \bmake\s+sure\b |
            # Imperative at start of request (common operator style)
            \A\s*(?:implement|fix|patch|refactor|rewrite|migrate|deploy|install|
              compile|commit|push|create|add|remove|delete|update|change|edit|write|
              run|execute|scan|probe|enumerate|discover|find|locate|audit|harden|
              resolve|debug|diagnose|investigate|optimize|configure|enable|disable|
              start|stop|restart|ship|finish|complete|break|decompose|ensure|verify|
              please)\b
          )
        /ix

        # Interrogatives that need a live local lookup (hostname, cwd, whoami…).
        # These are autonomous_goal so Loop uses tools — not text-only Q&A.
        NEEDS_LOCAL_EVIDENCE_RX = /
          \b(?:what(?:'?s|\s+is)|show|print|tell\s+me|get|echo|display|check)\b
          .{0,80}\b(?:
            (?:my\s+)?host\s*name|
            (?:my\s+)?(?:ip|ipv4|ipv6)(?:\s+address)?|
            (?:my\s+)?(?:cwd|pwd|working\s+directory|present\s+working\s+directory)|
            whoami|(?:my\s+)?user(?:name)?|(?:logged[- ]?in\s+)?user|
            (?:my\s+)?kernel|uname\b|
            uptime|disk\s+usage|free\s+space|memory\s+usage|
            listening\s+ports?|default\s+route|gateway|
            (?:this\s+)?(?:machine|host|box|system)\s+(?:name|hostname)
          )\b
        /ix

        KIND_SYSTEM = <<~SYS
                    You classify ONE user request for the pwn-ai agent.
                    Return ONLY one token from this set:
                      statement
                      question
                      autonomous_goal

                    Definitions:
                    - statement: FYI, observation, ack, or greeting. No work requested. No answer needed beyond a brief note.
                    - question: asks for knowledge, explanation, syntax, or prior-turn recall that can be answered without the agent performing multi-step host/code work. Do NOT plan tools.
                    - autonomous_goal: the agent must DO something — implement/fix/scan/run commands, or answer a fact that requires a live local lookup (hostname, cwd, whoami, listening ports, etc.).

                    Rules:
                    - "can you fix/implement/scan...?" is autonomous_goal even with a trailing ?
                    - "how to ..." / "what flags does X use" without "do it here" is question
                    - "what is my hostname?" / "what is my ip?" is autonomous_goal (needs tools)
          - "FYI the build is green" is statement
          - "suggest areas for improvement" / "what do you think" / review-opinion asks are question unless the user also says implement/fix/apply
          - Prefer autonomous_goal when unsure whether live action is required

                    Output: a single label token. No punctuation, no JSON, no prose.
        SYS

        # LLM request-kind classifier is ON by default (same knob family as plan LLM).
        # PWN::Env[:ai][:agent][:request_kind_llm] = false disables it (tests/airgap).
        # When unset, follows :task_summary_llm (false in unit specs).
        public_class_method def self.llm_kind_enabled?
          v = PWN::Env.dig(:ai, :agent, :request_kind_llm)
          return !!v unless v.nil?

          llm_plan_enabled?
        rescue StandardError
          true
        end

        public_class_method def self.request_kind(opts = {})
          req = opts[:request].to_s
          return :statement if req.strip.empty?

          # Injected precompute (tests / Loop hand-off).
          if opts.key?(:kind) && !opts[:kind].nil?
            parsed = parse_kind_label(raw: opts[:kind])
            return parsed if parsed
          end
          if opts.key?(:llm_kind)
            parsed = parse_kind_label(raw: opts[:llm_kind])
            return parsed if parsed
          end

          # Cheap deterministic intent (greeting/howto/recall/recon) — single
          # source with Loop.request_intent; avoids LLM on pure short-circuits.
          intent = nil
          if defined?(PWN::AI::Agent::Loop) && PWN::AI::Agent::Loop.respond_to?(:request_intent)
            begin
              intent = PWN::AI::Agent::Loop.request_intent(request: req)
              case intent
              when :greeting, :empty
                return :statement
              when :howto, :recall
                return :question
              when :recon_act
                return :autonomous_goal
              end
              # :act falls through — may still be statement/question/goal
            rescue StandardError
              # offline / load-order safe
            end
          end

          # Numbered operator checklist is always an autonomous goal.
          enumerated = begin
            extract_enumerated_steps(goal: req)
          rescue StandardError
            []
          end
          return :autonomous_goal if enumerated.length >= MIN_PLAN_TASKS

          # Review / opinion / "suggest areas" stay questions unless implement.
          return :question if req.match?(OPINION_REVIEW_RX) && !req.match?(IMPLEMENT_RX)

          # Strong agent-do / host-evidence before LLM (stable + offline).
          return :autonomous_goal if req.match?(AUTONOMOUS_GOAL_RX)
          return :autonomous_goal if req.match?(NEEDS_LOCAL_EVIDENCE_RX)

          # LLM classify ambiguous residual (prefer over brittle regex defaults).
          if !opts[:heuristic_only] && llm_kind_enabled?
            llm_k = llm_classify_kind(request: req)
            return llm_k if llm_k
          end
          # Explicit heuristic_only or LLM miss → offline rules.
          heuristic_request_kind(request: req, intent: intent)
        rescue StandardError
          :autonomous_goal
        end

        # Offline / fallback classifier (regex + length heuristics).
        public_class_method def self.heuristic_request_kind(opts = {})
          req = opts[:request].to_s
          return :statement if req.strip.empty?

          return :question if req.match?(OPINION_REVIEW_RX) && !req.match?(IMPLEMENT_RX)
          return :autonomous_goal if req.match?(AUTONOMOUS_GOAL_RX)
          return :autonomous_goal if req.match?(NEEDS_LOCAL_EVIDENCE_RX)
          return :question if req.match?(QUESTION_RX)
          return :statement if req.match?(STATEMENT_RX)

          stripped = req.gsub(/\s+/, ' ').strip
          # Short bare remarks are statements unless they look like work or Qs.
          if stripped.length < 48 && !stripped.match?(/\b(please|need|want|should|must)\b/i)
            return :question if stripped.include?('?')

            return :statement
          end

          :autonomous_goal
        rescue StandardError
          :autonomous_goal
        end

        # Normalize LLM / caller labels → kind symbol or nil.
        public_class_method def self.parse_kind_label(opts = {})
          raw = opts[:raw]
          return nil if raw.nil?

          s = raw.to_s.strip.downcase
          return nil if s.empty?

          # Prefer exact kind tokens anywhere in the response ("Label: question").
          tokens = s.gsub(/[^a-z_]/, ' ').split
          aliases = {
            'statement' => :statement, 'statements' => :statement,
            'fyi' => :statement, 'observation' => :statement,
            'ack' => :statement, 'greeting' => :statement,
            'question' => :question, 'questions' => :question,
            'query' => :question, 'howto' => :question,
            'how_to' => :question, 'recall' => :question,
            'autonomous_goal' => :autonomous_goal, 'goal' => :autonomous_goal,
            'task' => :autonomous_goal, 'act' => :autonomous_goal,
            'action' => :autonomous_goal, 'work' => :autonomous_goal,
            'do' => :autonomous_goal
          }
          tokens.each do |t|
            return aliases[t] if aliases.key?(t)
          end

          joined = tokens.join('_')
          return aliases[joined] if aliases.key?(joined)

          sym = s.to_sym
          KIND_LABELS.include?(sym) ? sym : nil
        rescue StandardError
          nil
        end

        # LLM classify path — Reflect/engine chat, no tools. Returns kind or nil.
        public_class_method def self.llm_classify_kind(opts = {})
          return nil unless llm_kind_enabled?

          req = opts[:request].to_s
          return :statement if req.strip.empty?

          raw = chat_for_kind(request: req)
          parse_kind_label(raw: raw)
        rescue StandardError => e
          warn "[pwn-ai/task_summarizer] llm_classify_kind swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Public so specs can stub the LLM boundary (mirrors chat_for_plan).
        public_class_method def self.chat_for_kind(opts = {})
          req = opts[:request].to_s
          system = KIND_SYSTEM
          user = "USER REQUEST:\n#{req}\n\nLabel:"
          if reflect_available?
            resp = Reflect.on(
              request: user,
              system_role_content: system,
              suppress_pii_warning: true,
              spinner: false
            )
            text = reflect_text(resp: resp)
            return text unless text.to_s.strip.empty?
          end

          engine_chat(request: user, system_role_content: system)
        rescue StandardError => e
          warn "[pwn-ai/task_summarizer] chat_for_kind swallowed: #{e.class}: #{e.message}"
          ''
        end

        # True only for autonomous goals — statements/questions skip multi-step plans.
        #
        # Supported Method Parameters::
        # yes = PWN::AI::Agent::TaskSummarizer.needs_task_breakdown?(
        #   request: 'optional - user text',
        #   kind: 'optional - precomputed request_kind'
        # )
        public_class_method def self.needs_task_breakdown?(opts = {})
          kind = opts[:kind]
          kind = request_kind(request: opts[:request]) if kind.nil?
          kind.to_sym == :autonomous_goal
        rescue StandardError
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
          goal = opts[:request].to_s.gsub(/\s+/, ' ').strip
          return [] if goal.empty?

          kind = opts[:request_kind]
          kind = (opts[:state][:request_kind] if opts[:state].is_a?(Hash)) if kind.nil?
          kind = request_kind(request: goal) if kind.nil?
          kind = kind.to_sym

          # Statements and questions: never multi-step task breakdown.
          # (Injected :tasks still honored for tests.)
          unless needs_task_breakdown?(kind: kind) || opts.key?(:tasks) || opts.key?(:llm_tasks)
            tasks = []
            source = :"no_breakdown_#{kind}"
            if opts[:state].is_a?(Hash)
              opts[:state][:plan] = tasks
              opts[:state][:request] = goal if opts[:state][:request].to_s.empty?
              opts[:state][:request_kind] = kind
              opts[:state][:plan_source] = source
            end
            return tasks
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
              tasks = fallback_decompose(goal: goal, request_kind: kind)
              source = :fallback
            end
          end

          tasks = normalize_task_list(tasks: tasks, goal: goal)
          if opts[:state].is_a?(Hash)
            opts[:state][:plan] = tasks
            opts[:state][:request] = goal if opts[:state][:request].to_s.empty?
            opts[:state][:request_kind] = kind
            opts[:state][:plan_source] = source
          end
          tasks
        rescue StandardError
          goal = opts[:request].to_s.gsub(/\s+/, ' ').strip
          kind = begin
            request_kind(request: goal)
          rescue StandardError
            :autonomous_goal
          end
          if goal.empty? || !needs_task_breakdown?(kind: kind)
            if opts[:state].is_a?(Hash)
              opts[:state][:plan] = []
              opts[:state][:request_kind] = kind
              opts[:state][:plan_source] = :"no_breakdown_#{kind}"
            end
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
          # Ensure a verify/close step when the model omitted one (act/recon only).
          list << 'Verify the result and report completion' unless list.last.to_s.match?(/verif|test|confirm|rubocop|rake|accept|done|close|summar|json|yaml|table|present|format|convert|report completion|report results/i)
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
          kind = opts[:request_kind]
          kind = request_kind(request: goal) if kind.nil? && !goal.empty?
          kind = kind.to_s.empty? ? nil : kind.to_sym

          # Statements / questions: no multi-step breakdown banner.
          if list.empty?
            return '' if goal.empty?

            case kind
            when :statement
              return "Request type: statement — no multi-step task breakdown\nNote: #{goal}"
            when :question
              return "Request type: question — no multi-step task breakdown\nQuestion: #{goal}"
            else
              return ''
            end
          end

          n = list.length
          lines = []
          lines << 'Request type: autonomous_goal' if kind == :autonomous_goal || kind.nil?
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

          request = state[:request].to_s
          request = opts[:request].to_s if request.empty?
          kind = state[:request_kind] || opts[:request_kind] || request_kind(request: request)
          state[:request_kind] = kind.to_sym
          tasks = state[:plan]
          # Decompose only when needed (autonomous goals, or empty plan not yet decided).
          tasks = plan(request: request, state: state, request_kind: kind) if tasks.nil? || Array(tasks).empty?
          text = format_plan(tasks: tasks, request: request, request_kind: kind)
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
          chunks
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
              spinner: false
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
            spinner: false
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
          goal_text = opts[:goal].to_s
          goal_lc = goal_text.downcase
          tasks = []

          # Statements / questions never get a synthetic multi-step fallback.
          kind = opts[:request_kind] || request_kind(request: goal_text)
          return [] unless needs_task_breakdown?(kind: kind)

          # If the operator already spelled improvement bullets, surface them.
          bullets = goal_text.scan(/(?:^|\s)(?:\d+\.|[-*])\s*([^.;]+)/).flatten.map(&:strip)
          if bullets.length >= MIN_PLAN_TASKS
            bullets.first(8).each { |b| tasks << b.sub(/\Athe\s+/i, '').sub(/\.\s*\z/, '') }
            return tasks
          end

          if howto_goal?(goal: goal_text)
            # how-to is a question kind; needs_task_breakdown? should already
            # have returned []. Keep belt-and-suspenders empty list.
            return []
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

        # Infer a plain-English "why" from the tool mix.
        # When a plan is active the goal is already on the plan line — keep why short
        # so each about_to batch stays distinct and is not a near-duplicate of the plan.
        private_class_method def self.why_bit(opts = {})
          names = opts[:names]
          caps = capabilities_for(names: names)
          focus =
            if caps.any? { |c| c.include?('shell') || c.include?('Ruby') }
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
          # Ensure plan exists only for autonomous goals (statements/questions
          # deliberately keep an empty plan — no multi-step breakdown).
          if state.is_a?(Hash) && Array(state[:plan]).empty? && !request.to_s.strip.empty?
            kind = state[:request_kind] || request_kind(request: request)
            state[:request_kind] ||= kind
            plan(request: request, state: state, request_kind: kind) if needs_task_breakdown?(kind: kind)
          end

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
          lines << '[pwn-ai/tasks] English tangible tasks are the SOLE driver of which tools execute next.'
          lines << 'Work the ACTIVE task to completion (many tools ok), then advance.'
          lines << 'Do not skip ahead. Do not pick tools from the original request alone or from any PLAN: tool-call scaffold.'
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

          info = active_task(state: state)
          return nil unless info

          force = !opts[:force].nil?
          prev = state[:focus_injected_idx]
          return nil if !force && !prev.nil? && prev.to_i == info[:idx].to_i

          state[:focus_injected_idx] = info[:idx]
          # First injection after plan: full plan_context. Later: compact focus.
          if prev.nil? || force
            plan_context(state: state)
          else
            done_bit =
              if state[:last_advanced_from]
                from = state[:last_advanced_from].to_i
                prev_item = Array(state[:plan])[from]
                prev_item ? "Completed task #{from + 1}. " : ''
              else
                ''
              end
            "#{done_bit}[pwn-ai/tasks] Now focus on #{info[:label]}. " \
              'English tangible tasks solely drive tool choice — call only tools needed for THIS task; ' \
              'ignore PLAN: tool scaffolds and do not skip remaining tasks.'
          end
        rescue StandardError
          nil
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
        # +1 streak matching the active task's tool intent -> advance once.
        # Any -1 or mistake fingerprint on the batch -> do not advance.
        #
        # Supported Method Parameters::
        # idx = PWN::AI::Agent::TaskSummarizer.apply_prm_advancement!(
        #   state: 'required - fresh() hash',
        #   rewards: 'required - Array of -1|0|1 (batch order)',
        #   intents: 'optional - Array of intent verb strings for the batch',
        #   names: 'optional - tool names in the batch',
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
          neu = rewards.count(&:zero?)
          # Require a clear +1 presence (not all-neutral).
          if pos.zero?
            state[:prm_pos_streak] = 0
            state[:last_prm_signal] = :hold_neutral
            return idx
          end

          item = plan[idx].to_s.downcase
          intents = Array(opts[:intents]).map { |iv| iv.to_s.downcase }.reject(&:empty?)
          names = Array(opts[:names]).map(&:to_s)

          # When intents given, require at least one matches the active task language.
          matched =
            if intents.empty? && names.empty?
              true
            else
              intent_s = (intents + names).join(' ')
              task_intent_match?(item: item, intent: intent_s)
            end

          unless matched
            state[:last_prm_signal] = :hold_intent_mismatch
            return idx
          end

          streak = state[:prm_pos_streak].to_i + pos
          state[:prm_pos_streak] = streak
          # Advance after a streak of >=2 positive steps (or a single full +1 batch of size>=2).
          should = streak >= 2 || (pos >= 2 && neu.zero?)
          if should
            state[:last_advanced_from] = idx
            state[:plan_idx] = idx + 1
            state[:prm_pos_streak] = 0
            state[:tools_on_task] = 0
            state[:last_prm_signal] = :advance
            return idx + 1
          end

          state[:last_prm_signal] = :streak
          idx
        rescue StandardError
          opts[:state].is_a?(Hash) ? opts[:state][:plan_idx].to_i : 0
        end

        # Does this intent string look like progress on the plan item?
        private_class_method def self.task_intent_match?(opts = {})
          item = opts[:item].to_s.downcase
          intent = opts[:intent].to_s.downcase
          return true if item.empty? || intent.empty?

          # Shared keyword stems between plan language and intent/tool verbs.
          stems = item.scan(/[a-z]{4,}/)
          return true if stems.empty?

          hit = stems.any? { |s| intent.include?(s[0, [s.length, 6].min]) }
          return true if hit

          # Coarse phase pairs (discovery vs mutate vs verify) - generic, not domain scripts.
          discovery = /locat|find|read|inspect|recon|understand|decompos|plan|determin|identif|gather|discover|list|enumerat|scan|probe/
          mutate    = /implement|fix|patch|chang|improv|edit|mutate|write|apply|wire|carry out|core work/
          verify    = /verif|test|rubocop|rake|spec|lint|confirm|accept|present|report|json|format/
          runish    = /run|script|eval|shell|pwn_eval|search|read|edit|test|mutate/

          return true if item.match?(discovery) && intent.match?(/search|read|recon|extro|sessions|memory|find|list|scan|#{runish.source}/)
          return true if item.match?(mutate) && intent.match?(/edit|mutate|eval|write|patch|#{runish.source}/)
          return true if item.match?(verify) && intent.match?(/test|eval|run|rubocop|rake|#{runish.source}/)

          # Soft default: positive PRM with no hard mismatch still counts when
          # the item is generic ("carry out the core work").
          item.match?(/carry out|core work|advance|perform|complete|finish|do the/)
        rescue StandardError
          true
        end

        # Nudge plan_idx forward when intents shift or enough tools have landed.
        private_class_method def self.maybe_advance_plan!(opts = {})
          state = opts[:state]
          names = opts[:names]
          intent = opts[:intent].to_s
          return unless state.is_a?(Hash)

          plan = Array(state[:plan])
          return if plan.length <= 1

          idx = state[:plan_idx].to_i
          return if idx >= plan.length - 1

          # Clearer advancement: require either a clear phase_shift AFTER the
          # active task has had some tool work, or a solid tools_on_task quota
          # with intent that still matches the active English task (completed).
          on_task = state[:tools_on_task].to_i
          item = plan[idx].to_s.downcase
          name_s = Array(names).join(' ')
          matched = task_intent_match?(item: item, intent: "#{intent} #{name_s}")
          phase_shift = false
          if intent != ''
            # Intent-driven advance (generic phase language - not domain scripts).
            phase_shift =
              (item.match?(/locat|find|read|inspect|recon|understand|decompos|plan|determin|identif|gather|discover/) &&
                intent.match?(/edit|mutate|test|vcs|run|script|eval/)) ||
              (item.match?(/implement|fix|patch|chang|improv|display|wire|carry out|core work|probe|scan|enumerat/) &&
                intent.match?(/test|rubocop|rake|eval|mutate/)) ||
              (item.match?(/aggregat|collect|combin/) &&
                intent.match?(/eval|mutate|script|run/)) ||
              (item.match?(/json|yaml|table|format|convert|present|report|verif/) &&
                intent.match?(/eval|mutate|script|test|run/)) ||
              (name_s.match?(/extro_/) && item.match?(/code|source|implement|rubocop/)) ||
              (name_s.match?(/memory_|sessions_/) && item.match?(/scan|probe|discover|recon/))
          end
          # Advance when phase clearly moves after >=1 tool on this task, OR
          # after >=3 successful-ish tools still on this task (completion quota).
          should = (phase_shift && on_task >= 2) || (on_task >= 3 && matched)
          if should
            state[:last_advanced_from] = idx
            state[:plan_idx] = idx + 1
            state[:tools_on_task] = 0
            state[:last_prm_signal] = :advance_phase if state[:last_prm_signal] != :advance
          end
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
            mistake: mistake_hit
          )
          # Heuristic phase-shift remains as a backstop when PRM streak has not fired.
          if state[:last_prm_signal] != :advance
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
              # On user submit — autonomous goals only: LLM breaks into tangible tasks:
              kind = PWN::AI::Agent::TaskSummarizer.request_kind(request: state[:request])
              # => :statement | :question | :autonomous_goal
              plan = PWN::AI::Agent::TaskSummarizer.plan(request: state[:request], state: state)
              # statements/questions => []; autonomous goals => ordered work units
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
