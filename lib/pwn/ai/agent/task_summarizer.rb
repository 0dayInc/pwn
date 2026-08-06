# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # High-level executive brief of the work the agent is about to do.
      #
      # Two layers (both shown in full on the pwn-ai task line):
      #   1. plan(request) — on user submit, break the goal into an ordered
      #      list of tangible tasks (each task is a coherent unit that may
      #      require many tool calls).
      #   2. about_to(tools:) — per tool-batch brief under the active plan
      #      item (one-to-many: one task line, many subsequent tool lines).
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

        module_function

        def enabled?
          v = PWN::Env.dig(:ai, :agent, :task_summary)
          v.nil? || !!v
        rescue StandardError
          true
        end

        def verbose?
          !!PWN::Env.dig(:ai, :agent, :task_summary_verbose)
        rescue StandardError
          false
        end

        def every_n
          n = PWN::Env.dig(:ai, :agent, :task_summary_every)
          n = DEFAULT_EVERY if n.nil?
          [n.to_i, 1].max
        rescue StandardError
          DEFAULT_EVERY
        end

        def interval_s
          t = PWN::Env.dig(:ai, :agent, :task_summary_interval_s)
          t = DEFAULT_INTERVAL_S if t.nil?
          [t.to_f, 1.0].max
        rescue StandardError
          DEFAULT_INTERVAL_S
        end

        # Per-run state (also safe for nested/swarm if callers keep their own hash)
        def fresh(opts = {})
          {
            request: opts[:request].to_s,
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
            batch_seq: 0
          }
        end

        # Map a tool name to a short human capability label (no args).
        def capability_label(name)
          tool = name.to_s
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
          "use #{name}"
        end

        # Group tool names into ordered unique capability phrases.
        def capabilities_for(names)
          Array(names).map { |n| capability_label(n) }.uniq
        end

        # "shell×3, pwn_eval×1" — distinctive when only tools change.
        def tool_counts_phrase(names)
          counts = Hash.new(0)
          Array(names).each { |n| counts[n.to_s] += 1 if n.to_s != '' }
          return '' if counts.empty?

          counts.map { |n, c| c > 1 ? "#{n}×#{c}" : n }.join(', ')
        rescue StandardError
          Array(names).map(&:to_s).reject(&:empty?).join(', ')
        end

        # Short intent verbs from tool args (no paths/commands dumped).
        # Makes two shell batches distinguishable (search vs edit vs test).
        def intent_phrase(tools)
          intents = []
          Array(tools).each do |tool|
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

        def brief_fingerprint(line)
          line.to_s.gsub(/\s+/, ' ').strip.downcase
        rescue StandardError
          line.to_s
        end

        # True when this brief is effectively the same task line we already showed.
        # A1: also cross-dedup against the full plan blob so about_to cannot
        # restate text emit_plan! just printed (plan vs about_to FPs differ).
        def duplicate_brief?(state, line)
          return false unless state.is_a?(Hash)

          fp = brief_fingerprint(line)
          return false if fp.empty?
          return true if state[:last_brief_fp] == fp

          # Near-duplicate of the full plan blob (should not happen, but cheap).
          plan_fp = brief_fingerprint(state[:plan_text])
          return true if !plan_fp.empty? && fp == plan_fp

          false
        rescue StandardError
          false
        end

        def remember_brief!(state, line)
          return line unless state.is_a?(Hash)

          state[:last_brief] = line
          state[:last_brief_fp] = brief_fingerprint(line)
          state[:batch_seq] = state[:batch_seq].to_i + 1
          line
        rescue StandardError
          line
        end

        # ------------------------------------------------------------------
        # Request → ordered tangible tasks (each may map to many tools).
        # Called once when the user submits a request.
        # ------------------------------------------------------------------
        def plan(request, opts = {})
          goal = request.to_s.gsub(/\s+/, ' ').strip
          return [] if goal.empty?

          tasks = []
          # Prefer explicit enumerated steps already in the request (1. / 2. / - ).
          enumerated = extract_enumerated_steps(goal)
          if enumerated.length >= 2
            tasks = enumerated
          else
            tasks = heuristic_decompose(goal)
          end

          # Ensure at least one concrete task. A2: always append a verify/close
          # step (even for one-task goals) so plans are work+verify and the
          # mid-flight about_to line can track 1/2 -> 2/2 without restating a
          # solitary Carry-out line as the entire brief.
          tasks = ["Carry out: #{goal}"] if tasks.empty?
          tasks << 'Verify the result and report completion' unless tasks.last.to_s.match?(/verif|test|confirm|rubocop|rake|accept|done|close|summar/i)

          tasks = tasks.map { |t| t.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?).uniq
          tasks = tasks.first(12)

          if opts[:state].is_a?(Hash)
            opts[:state][:plan] = tasks
            opts[:state][:request] = goal if opts[:state][:request].to_s.empty?
          end
          tasks
        rescue StandardError
          goal = request.to_s.gsub(/\s+/, ' ').strip
          goal.empty? ? [] : ["Carry out: #{goal}"]
        end

        # Format the full plan as the task-summary body (shown in entirety).
        def format_plan(tasks, request = nil)
          list = Array(tasks).map(&:to_s).reject(&:empty?)
          return '' if list.empty?

          goal = request.to_s.gsub(/\s+/, ' ').strip
          lines = []
          lines << "Goal: #{goal}" unless goal.empty?
          lines << "Tangible tasks (#{list.length}) — each may use many tools:"
          list.each_with_index do |t, i|
            lines << "  #{i + 1}. #{t}"
          end
          lines.join("\n")
        rescue StandardError
          Array(tasks).map.with_index(1) { |t, i| "#{i}. #{t}" }.join("\n")
        end

        # Emit plan once at loop start. Returns full plan text (no truncation).
        def emit_plan!(state, opts = {})
          return nil unless state.is_a?(Hash)
          return state[:plan_text] if state[:plan_emitted] && state[:plan_text]

          request = state[:request].to_s
          request = opts[:request].to_s if request.empty?
          tasks = state[:plan]
          tasks = plan(request, state: state) if tasks.nil? || Array(tasks).empty?
          text = format_plan(tasks, request)
          state[:plan] = Array(tasks)
          state[:plan_text] = text
          state[:plan_emitted] = true
          state[:plan_idx] = 0
          remember_brief!(state, text)
          text
        rescue StandardError
          nil
        end

        def extract_enumerated_steps(goal)
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
          if chunks.length < 2
            # Inline: "1. do X 2. do Y 3. do Z"
            inline = goal.scan(/(?:^|\s)\d+[.):]\s+([^\d]+?)(?=(?:\s+\d+[.):]\s+)|$)/)
            chunks = inline.flatten.map(&:strip) if inline.length >= 2
          end
          if chunks.length < 2
            # Numbered improvement list like "1. the task ... 2. once a request"
            inline = goal.split(/(?=(?:^|\s)\d+\.\s+)/).map(&:strip).reject(&:empty?)
            chunks = inline.map { |c| c.sub(/\A\d+\.\s+/, '') }.reject(&:empty?) if inline.length >= 2
          end
          chunks
        rescue StandardError
          []
        end

        def heuristic_decompose(goal)
          g = goal.to_s
          gl = g.downcase
          tasks = []

          # Locate / recon
          tasks << 'Locate relevant source files and call sites' if gl.match?(/\b(find|locat|where|search|grep|rg |discover|identif)/)

          # Read / understand
          tasks << 'Read and understand the current implementation' if gl.match?(/\b(read|review|inspect|understand|analy[sz]|audit|examin)/)

          # Fix / improve / implement
          if gl.match?(/\b(fix|improv|implement|add|remove|refactor|updat|chang|wire|patch|nerds|needs)/)
            # Pull concrete improvement bullets if present
            bullets = g.scan(/(?:^|\s)(?:\d+\.|[-*])\s*([^.;]+)/).flatten.map(&:strip)
            if bullets.length >= 2
              bullets.first(8).each { |b| tasks << b.sub(/\Athe\s+/i, '').sub(/\.\s*\z/, '') }
            else
              tasks << "Implement the requested change: #{truncate_goal(g, 160)}"
            end
          elsif tasks.empty?
            # Generic actionable goal
            tasks << "Execute the request: #{truncate_goal(g, 160)}"
          end

          # Display / UI
          tasks << 'Ensure full task summary is displayed in pwn-ai (no truncation)' if gl.match?(/\b(display|show|print|emit|ui|repl|tui|entire|full|truncat)/) && tasks.none? { |t| t.to_s.match?(/display|truncat|full|summary/i) }

          # Breakdown / plan
          tasks << 'Decompose each user request into ordered tangible tasks' if gl.match?(/\b(break\s*down|decompos|tangible|plan|list of|sub-?tasks)/) && tasks.none? { |t| t.to_s.match?(/decompos|tangible|break/i) }

          # Test / lint
          tasks << 'Run specs, rubocop, and/or rake to verify' if gl.match?(/\b(test|spec|rubocop|rake|lint|verify|accept)/)

          # Report
          tasks << 'Summarize what changed and confirm acceptance criteria' if gl.match?(/\b(report|document|summar|explain|answer)/)

          tasks = tasks.map { |t| t.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?).uniq
          tasks = ["Carry out: #{truncate_goal(g, 200)}"] if tasks.empty?
          tasks
        rescue StandardError
          ["Carry out: #{truncate_goal(goal, 200)}"]
        end

        def truncate_goal(goal, _len = nil)
          # Task summaries are displayed in full — do not ellipsize goals or
          # plan items. (_len retained for call-site compatibility.)
          goal.to_s.gsub(/\s+/, ' ').strip
        end

        # Infer a plain-English "why" from the tool mix.
        # When a plan is active the goal is already on the plan line — keep why short
        # so each about_to batch stays distinct and is not a near-duplicate of the plan.
        def why_bit(request, names, opts = {})
          caps = capabilities_for(names)
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
            goal = request.to_s.gsub(/\s+/, ' ').strip
            return goal.empty? ? focus : "#{focus} toward: #{goal}"
          end
          focus
        rescue StandardError
          ''
        end

        # High-level brief for a collection of impending tool calls.
        # This string appears as name='task' and is shown in FULL in pwn-ai.
        #
        # opts:
        #   :tools   => array of {name:, args:} or bare names (preferred)
        #   :name    => single tool (legacy one-tool path)
        #   :args    => single tool args (ignored for brief content)
        #   :request => goal text
        #   :state   => fresh() hash
        def about_to(name_or_nil = nil, args = nil, opts = {})
          # Support about_to(opts) and about_to(name, args, opts)
          if name_or_nil.is_a?(Hash) && args.nil? && opts.empty?
            opts = name_or_nil
            name_or_nil = nil
          end

          state   = opts[:state]
          request = state && state[:request].to_s
          request = opts[:request].to_s if request.nil? || request.empty?

          tools = normalize_tools(opts[:tools], name_or_nil, args)
          names = tools.map { |t| t[:name] }
          # Always ensure plan exists so mid-flight briefs can cite tangible tasks.
          plan(request, state: state) if state.is_a?(Hash) && Array(state[:plan]).empty? && !request.to_s.strip.empty?

          caps = capabilities_for(names)
          counts = tool_counts_phrase(names)
          intent = intent_phrase(tools)

          what =
            if caps.empty?
              'Prepare the next step'
            elsif intent != '' && counts != ''
              # Distinctive: tools + intent so shell/search ≠ shell/edit
              "Next: #{counts} (#{intent})"
            elsif counts != ''
              "Next: #{counts}"
            elsif caps.length == 1
              "Next: #{caps.first}"
            else
              head = caps[0..-2].join(', ')
              "Next: #{head}, and #{caps.last}"
            end

          # Tie batch to active plan item when available.
          # A1/A3: emit_plan! already printed Goal + full numbered list. The first
          # about_to after that (batch_seq <= 1) must not restate "[task 1/N: ...]"
          # keep only tool/intent so the TUI is not a double display. Same for
          # truly single-task plans *after* the plan line was shown. Later batches
          # re-attach plan_bit so progress against 1/2 -> 2/2 remains visible.
          # When plan() was only auto-seeded and emit_plan! never ran, always keep
          # [task k/N] (or toward: below) so the brief still has plan/goal linkage.
          plan_bit = ''
          has_plan = state.is_a?(Hash) && Array(state[:plan]).any?
          plan_emitted = state.is_a?(Hash) && state[:plan_emitted]
          if has_plan
            idx = active_plan_index(state)
            item = state[:plan][idx]
            if item
              state[:plan_idx] = idx if state.is_a?(Hash)
              plan_n = state[:plan].length
              first_after_plan = plan_emitted && state[:batch_seq].to_i <= 1 && idx.zero?
              omit_plan_bit = first_after_plan || (plan_n <= 1 && plan_emitted)
              plan_bit = " [task #{idx + 1}/#{plan_n}: #{item}]" unless omit_plan_bit
            end
          end

          # Goal lives on the emit_plan! line. Restate toward: only when this
          # brief would otherwise have no plan/goal linkage (no plan at all, or
          # plan auto-seeded but never emitted and plan_bit empty).
          why = why_bit(
            request,
            names,
            with_goal: plan_bit.empty? && !plan_emitted
          )
          line = why.empty? ? "#{what}#{plan_bit}" : "#{what}#{plan_bit} — #{why}"
          line = line.gsub(/[^\S\n]+/, ' ').strip
          # Full summary — never ellipsize. Pathological multi-MB blobs only
          # get a hard safety clamp far above normal executive briefs.
          line = line[0, 50_000] if line.length > 50_000

          # Suppress identical task lines when the model re-issues the same batch.
          if state.is_a?(Hash) && duplicate_brief?(state, line)
            state[:pending_tools] = names
            state[:emitted_for_batch] = true
            return nil
          end

          if state.is_a?(Hash)
            remember_brief!(state, line)
            state[:pending_tools] = names
            state[:emitted_for_batch] = true
          end
          line
        rescue StandardError
          'Next: advance the current goal'
        end

        def active_plan_index(state)
          plan = Array(state[:plan])
          return 0 if plan.empty?

          # Prefer explicit plan_idx when set (advanced by maybe_advance_plan!).
          explicit = state[:plan_idx].to_i
          return explicit.clamp(0, plan.length - 1) if state.key?(:plan_idx) && explicit.positive?

          total = state[:total].to_i
          return 0 if total <= 0

          # Spread tools across plan items; keep last item for the final third.
          n = plan.length
          return 0 if n <= 1

          # ~equal buckets; final item reserved until >= 2/3 of expected work.
          per = [3, 4].max
          bucket = (total / per.to_f).floor
          [bucket, n - 1].min
        rescue StandardError
          0
        end

        # Nudge plan_idx forward when intents shift or enough tools have landed.
        def maybe_advance_plan!(state, _names = [], intent = '')
          return unless state.is_a?(Hash)

          plan = Array(state[:plan])
          return if plan.length <= 1

          idx = state[:plan_idx].to_i
          return if idx >= plan.length - 1

          total = state[:total].to_i
          # Advance every ~3 tools, or when intent verbs clearly move on.
          should = total.positive? && (total % 3).zero?
          if !should && intent.to_s != ''
            item = plan[idx].to_s.downcase
            # Intent-driven advance (single assignment path avoids DuplicateBranch).
            phase_shift =
              (item.match?(/locat|find|read|inspect|recon|understand|decompos|plan/) &&
                intent.match?(/edit|mutate|test|vcs/)) ||
              (item.match?(/implement|fix|patch|chang|improv|display|wire/) &&
                intent.match?(/test|rubocop|rake/))
            should = true if phase_shift
          end
          state[:plan_idx] = idx + 1 if should
        rescue StandardError
          nil
        end

        def normalize_tools(tools, name, args)
          list = Array(tools)
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

        # Kept for debug/verbose only — never the primary task UX.
        def arg_snippet(args)
          return '' unless verbose?

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
        def record!(state, name, args, result)
          return nil unless state

          preview = verbose? ? arg_snippet(args).to_s[0, 60] : ''
          rs = result.to_s
          ok = !rs.match?(/\A\s*\{?\s*"?(success|ok)"?\s*=>\s*false/i) &&
               !rs.match?(/ERROR:|Traceback|NoMethodError|StandardError/i)
          state[:events] << { name: name.to_s, preview: preview, ok: ok, t: Time.now }
          state[:events].shift while state[:events].size > MAX_BUFFER
          state[:counts][name.to_s] += 1
          state[:total] += 1
          state[:since_emit] += 1
          state[:emitted_for_batch] = false
          maybe_advance_plan!(state, [name.to_s], intent_phrase([{ name: name.to_s, args: args }]))

          # Default: no mid-flight task spam. Progress lines only when verbose.
          return nil unless verbose?

          due = state[:since_emit] >= every_n ||
                (Time.now - state[:last_emit_at]) >= interval_s
          due ? emit!(state) : nil
        end

        # Optional progress / done line (verbose or flush). Still plain English;
        # never includes raw tool results. Shown in full (no 60-char goal cut).
        def emit!(state, final: false)
          return nil if state.nil? || state[:events].empty?

          counts = state[:counts].sort_by { |_, c| -c }.map { |n, c| "#{n}×#{c}" }
          recent = state[:events].last([every_n, 1].max)
          caps = capabilities_for(recent.map { |e| e[:name] })
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
          plan_bit = " | plan: #{state[:plan].length} tangible tasks" if Array(state[:plan]).any?
          state[:since_emit] = 0
          state[:last_emit_at] = Time.now
          "#{phase}: #{focus} — #{state[:total]} tool calls so far (#{counts.first(6).join(', ')})#{fail_bit}#{goal_bit}#{plan_bit}"
        end

        def flush!(state)
          emit!(state, final: true)
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
              # On user submit — full tangible-task breakdown (shown in entirety):
              plan = PWN::AI::Agent::TaskSummarizer.plan(state[:request], state: state)
              text = PWN::AI::Agent::TaskSummarizer.emit_plan!(state)
              # → "Goal: ...\nTangible tasks (N) — each may use many tools:\n  1. ...\n  2. ..."
              # UI: on_tool.call('task', text, '')  # full text, no truncation
              # One task brief for a whole tool collection (one-to-many):
              pre = PWN::AI::Agent::TaskSummarizer.about_to(
                tools: [{ name: 'shell' }, { name: 'pwn_eval' }],
                state: state
              )
              # → "Next: run shell commands, and evaluate Ruby ... [task k/N: ...] — toward: ..."
              # then real tools print on their own lines; record! stays silent by default
              PWN::AI::Agent::TaskSummarizer.record!(state, 'shell', 'ls', '{success:true}')
              line = PWN::AI::Agent::TaskSummarizer.flush!(state)  # optional closing brief
              PWN::AI::Agent::TaskSummarizer.enabled?
              PWN::AI::Agent::TaskSummarizer.verbose?
              PWN::AI::Agent::TaskSummarizer.every_n
              PWN::AI::Agent::TaskSummarizer.interval_s

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
