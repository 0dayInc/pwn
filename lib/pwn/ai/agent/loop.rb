# frozen_string_literal: true

require 'json'
require 'securerandom'
require 'digest'
require 'pwn/ai/agent/mistakes'

module PWN
  module AI
    module Agent
      # The agent conversation loop:
      #
      #   build system prompt → call LLM with tools → if tool_calls: dispatch,
      #   append role:'tool' results, loop → else: return text.
      #
      # This replaces the regex-ReAct in PWN::Plugins::REPL :pwn_ai_hook with
      # native function-calling. State (memory, skills, sessions) is all
      # externalised — Loop.run is stateless aside from the messages array it
      # builds.
      #
      # NEGATIVE-FEEDBACK CLOSURE
      # -------------------------
      # Loop.run is where "learn from mistakes, don't repeat them" is
      # actually enforced. On EVERY failed dispatch it:
      #   1. Records the (tool, normalised_error) fingerprint into
      #      PWN::AI::Agent::Mistakes with a PERSISTENT cross-session count.
      #   2. Reads that count back and, if it OR the in-turn count reaches
      #      REPEAT_THRESHOLD, prepends a hard "REPEATED FAILURE — change
      #      approach" guard to the tool result the model sees next.
      #   3. Appends Mistakes.correction_hint (seen N×, sig, KNOWN FIX: …)
      #      so a previously-discovered fix is handed straight back to the
      #      model on the FIRST recurrence in a new session — it does not
      #      have to fail 3× again to re-learn what it already knew.
      # PromptBuilder.mistakes_block re-injects the top open mistakes and
      # top known fixes into the system prompt of every future turn.
      #
      # COMPLETION
      # ----------
      # The original request is the completion signal. TaskSummarizer and
      # Policy are advisory (compass / rank). Loop keeps calling CORE_TOOLS
      # until that request is done or truly blocked, then stops.
      #
      # LOCAL-MODEL SCAFFOLDING
      # -----------------------
      # When the active engine is :ollama (or the corresponding :agent flags
      # are set) Loop.run additionally:
      #   * threads request → PromptBuilder for relevance-ranked MEMORY,
      #   * threads request → Registry.definitions(relevance:) for a slimmed
      #     tool set (:tool_router),
      #   * splices Learning.exemplars_for(request:) between system and user
      #     as few-shot behaviour retrieval,
      #   * runs a plan-then-act pre-pass (:plan_first) so the model
      #     externalises a tool plan before its first dispatch,
      #   * escalates to a frontier persona for a 3-line corrective hint
      #     once ≥ ESCALATE_AFTER_FAILS in-turn failures accumulate
      #     (:escalation_persona) — the local model still produces the final
      #     answer so Learning/Metrics stay attributed to :ollama.
      module Loop
        DEFAULT_MAX_ITERS    = 777
        ESCALATE_AFTER_FAILS = 4
        # P17 — when empty_final / known thrash shapes dominate, stop before
        # burning the full ollama cap so the corpus is not pure terminal failure.
        BUDGET_HARD_STOP_FAILS = 8
        BUDGET_EMPTY_FINAL_STOP = 3

        ENGINE_MODS = {
          openai: 'PWN::AI::OpenAI',
          grok: 'PWN::AI::Grok',
          ollama: 'PWN::AI::Ollama',
          openwebui: 'PWN::AI::OpenWebUI',
          anthropic: 'PWN::AI::Anthropic',
          gemini: 'PWN::AI::Gemini'
        }.freeze

        private_class_method def self.degrade_text_only(opts = {})
          mod      = opts[:mod]
          messages = opts[:messages]

          warn "[pwn-ai] #{mod} has no chat — falling back to text-only (no tool-calling)"
          sys  = messages.find { |m| m[:role] == 'system' }
          user = messages.rfind { |m| m[:role] == 'user' }
          r = mod.chat(
            request: user[:content],
            system_role_content: sys&.[](:content),
            spinner: true
          )

          txt = r.is_a?(Hash) ? (r.dig(:choices, -1, :content) || r.dig(:choices, -1, :text)).to_s : r.to_s
          { role: 'assistant', content: txt, tool_calls: [] }
        end

        # P17 — true when RECENT unresolved agent_loop / assistant_answer budget
        # fingerprints dominate Mistakes.top. Sliding window + auto-cool so the
        # loop's own exhaust-path Mistakes.record cannot permanently latch hot
        # (scar 8ec3303ed69e self-latch). Do NOT deepen caps; cool the detector.
        HOT_WINDOW_SECS     = 48 * 3600
        HOT_COOL_MAX_RECENT = 1 # <=1 budget hit in window => cooled (not hot)

        private_class_method def self.budget_hit?(opts = {})
          mistake = opts[:mistake] || opts[:m] || opts
          tool = mistake[:tool].to_s
          err = mistake[:error].to_s.downcase
          shape = (mistake[:shape] || mistake['shape']).to_s
          budget_shape = %w[budget_exhausted budget_thrash].include?(shape)
          budget_err = err.include?('budget exhausted') ||
                       err.include?('iteration budget') ||
                       err.include?('budget thrash')
          # Only budget-shaped agent_loop / assistant_answer rows count.
          # Prior "any agent_loop tool" match permanently latched hot on unrelated
          # loop failures (scar 8ec3303ed69e self-latch).
          (%w[agent_loop assistant_answer].include?(tool) && (budget_shape || budget_err)) ||
            budget_err
        rescue StandardError
          false
        end

        private_class_method def self.mistake_ts(opts = {})
          mistake = opts[:mistake] || opts[:m] || opts
          stamp = (mistake[:last_seen] || mistake[:updated_at] || mistake[:first_seen]).to_s
          Time.parse(stamp)
        rescue StandardError
          nil
        end

        # P17 rate-based cool/park for permanent budget scars (8ec3303ed69e).
        # Leaves scar open but parks it so it stops dominating Mistakes.top.
        # Resolve is rate-based only (external / after multi-day cool) — never
        # because a guard patch landed. PARK_COOL_SECS (24h) is intentionally
        # shorter than HOT_WINDOW (48h): once hot?=false, a single cooled scar
        # must not keep owning Mistakes.top for another full day.
        PARK_COOL_SECS = 24 * 3600

        PRIVILEGED_TOOLSETS = %w[cron swarm].freeze
        SNAPSHOT_STALE_SECS = 6 * 3600

        private_class_method def self.default_interactive_toolsets(opts = {})
          req = opts[:request].to_s
          all = defined?(Registry) ? Registry.toolsets.map(&:to_s) : []
          drop = PRIVILEGED_TOOLSETS.dup
          drop.delete('swarm') if req.match?(/\b(swarm|persona|debate|agent_ask|multi-agent)\b/i)
          drop.delete('cron') if req.match?(/\b(cron|schedule|nightly job)\b/i)
          all - drop
        end

        private_class_method def self.maybe_refresh_extro_snapshot!
          return unless defined?(Extrospection)

          captured = nil
          begin
            stats = Extrospection.stats if Extrospection.respond_to?(:stats)
            captured = stats[:snapshot_captured_at] || stats[:captured_at] if stats.is_a?(Hash)
          rescue StandardError
            captured = nil
          end
          stale = captured.to_s.empty?
          if captured && !stale
            age = Time.now.utc - Time.parse(captured.to_s)
            stale = age > SNAPSHOT_STALE_SECS
          end
          return unless stale

          Extrospection.snapshot(persist: true, sections: %w[host repo env]) if Extrospection.respond_to?(:snapshot)
        rescue StandardError
          nil
        end

        private_class_method def self.maybe_park_budget_scars!
          return unless defined?(Mistakes)
          return unless Mistakes.respond_to?(:park)

          top = Mistakes.top(limit: 24, unresolved_only: true)
          now = Time.now
          budget = top.select { |mistake| budget_hit?(mistake: mistake) && !mistake[:parked] }
          budget.each do |mistake|
            stamp = mistake_ts(mistake: mistake)
            next if stamp && (now - stamp) <= PARK_COOL_SECS

            Mistakes.park(
              signature: mistake[:signature].to_s,
              reason: 'p17 rate-cool: outside PARK_COOL_SECS'
            )
          end
          live = budget.reject do |mistake|
            row = Mistakes.find(signature: mistake[:signature].to_s)
            row.nil? || row[:parked]
          end
          return if live.length <= 1

          # Never let 2+ budget scars latch hot forever. Keep only the newest.
          live.sort_by { |mistake| mistake_ts(mistake: mistake) || Time.at(0) }[0...-1].each do |mistake|
            Mistakes.park(
              signature: mistake[:signature].to_s,
              reason: 'p17 keep-newest budget scar; extras parked so tomorrow is not hot'
            )
          end
        rescue StandardError
          nil
        end

        private_class_method def self.maybe_extinguish_parked!
          return unless defined?(Mistakes) && Mistakes.respond_to?(:extinguish_parked!)

          Mistakes.extinguish_parked!(limit: 12)
        rescue StandardError
          nil
        end

        private_class_method def self.budget_exhaustion_hot?
          return false unless defined?(Mistakes)

          top = Mistakes.top(limit: 24, unresolved_only: true)
          return false if top.empty?

          now = Time.now
          recent = top.select do |mistake|
            next false if mistake[:parked]

            stamp = mistake_ts(mistake: mistake)
            stamp.nil? || (now - stamp) <= HOT_WINDOW_SECS
          end
          return false if recent.empty?

          budgetish = recent.count { |mistake| budget_hit?(mistake: mistake) }
          # Auto-cool: old unresolved scar alone must not keep the host hot.
          return false if budgetish <= HOT_COOL_MAX_RECENT

          budgetish >= 2 || (budgetish >= 1 && recent.first[:tool].to_s == 'agent_loop')
        rescue StandardError
          false
        end

        # P17 — evidence-enough early final: latest tool rounds already answer
        # the original request → force synthesis. English tasks are an advisory
        # compass only — an open verify tail must not block a finished ask.
        # The original request is the completion signal.
        private_class_method def self.evidence_enough_to_finalize?(opts = {})
          messages = Array(opts[:messages])
          turn_fails = opts[:turn_fails] || {}
          iter = opts[:i].to_i
          max_i = opts[:max_iters].to_i
          request = opts[:request].to_s
          return false if max_i <= 0 || iter < 2
          return false if turn_fails['empty_final'].to_i.positive?
          return false if turn_fails['incomplete_final'].to_i > 1

          fail_n = turn_fails.values.sum
          return false if fail_n >= 3

          tools_ok = messages.select { |msg| msg[:role].to_s == 'tool' }
          return false if tools_ok.size < 2

          last2 = tools_ok.last(2)
          return false if last2.any? do |msg|
            content = msg[:content].to_s
            content.match?(/traceback|error:|exception|budget exhausted|syntax error/i) &&
            !content.match?(/"success"\s*:\s*true/i)
          end

          plan_steps = opts[:plan_steps].to_i
          short_plan = plan_steps.positive? && plan_steps <= 3
          deep_enough = tools_ok.size >= 3 || (short_plan && tools_ok.size >= plan_steps)
          return false unless deep_enough

          recent_txt = last2.map { |msg| msg[:content].to_s[0, 500] }.join(' ')
          mutation_done = recent_txt.match?(
            /syntax ok|wrote |patched|File\.write|ruby -c|0 offenses|examples?,\s*0 failures/i
          )
          return true if mutation_done
          return true if short_plan && tools_ok.size >= plan_steps && fail_n.zero? &&
                         request.match?(/\b(what|who|when|where|which|how many|status|list|show|print|uname|cwd|version|hostname)\b/i)

          false
        rescue StandardError
          false
        end

        # P28 — incomplete / handoff finals: model emitted text-only before the
        # goal was done ("shall I proceed?", "next step:", "want me to…").
        # Loop.run treats no-tool_calls as FINAL; this detector lets us refuse
        # that handoff and keep the tool loop alive for multi-step autonomy.
        #
        # Local/thinking models (gemma/Qwen abliterated etc.) often emit a
        # monologue that NARRATES the next tool ("Wait, let's try hping3…")
        # without producing native tool_calls or shell(...). Treat that as
        # incomplete too so the loop re-pressures tools instead of FINAL.
        INCOMPLETE_FINAL_RX = /
          \b(shall\s+i|should\s+i|may\s+i|can\s+i|want\s+me\s+to|do\s+you\s+want\s+me|
             next\s+single\s+step|next\s+step\s*:|awaiting\s+your\s+(ok|approval|go-ahead|confirmation)|
             if\s+you(?:'d|\s+would)\s+like\s+me\s+to|say\s+the\s+word|confirm\s+(before|and\s+i)|
             ready\s+to\s+proceed|ok\s+to\s+(proceed|continue|apply)|proceed\?|
             continue\?|before\s+i\s+(apply|change|run|continue|proceed)|
             once\s+you\s+(confirm|approve)|let\s+me\s+know\s+if|
             i(?:'ll|\s+will)\s+wait\b|waiting\s+for\s+(your\s+)?(go|ok|approval|confirmation)
          )\b
        /ix

        # Narrated-intent monologue without a structured tool call.
        # Distinct from INCOMPLETE_FINAL_RX (polite handoff to the human).
        MONOLOGUE_TOOL_INTENT_RX = /
          \b(
            wait[,\s]+let'?s\s+try|
            let'?s\s+try\s+(one|to|again|hping|nmap|ping|sudo|shell|running|checking)|
            i\s+(?:will|'ll)\s+(?:just\s+)?(?:try|run|check|probe|scan|use)\b|
            actually,?\s+i\s+will\b|
            one\s+more\s+thing\b|
            if\s+it\s+fails\b.{0,80}\bthen\s+we\s+can\b|
            verification\s+complete\b|
            report\s+that\s+(?:the\s+)?verification\s+failed\b
          )
        /ix

        private_class_method def self.incomplete_final?(opts = {})
          text = opts[:text].to_s
          return false if text.strip.empty?
          # Hard last-iter forces a real final; do not bounce that forever.
          return false if opts[:last_iter]
          return true if text.match?(INCOMPLETE_FINAL_RX)
          # Short status-only dumps with a trailing question are handoffs.
          return true if text.include?('?') && text.length < 900 &&
                         text.match?(/\b(proceed|continue|confirm|apply|next)\b/i)

          # Thinking/monologue that plans tools in prose (esp. Ollama gemma).
          # Cap length so a real long final answer is not bounced forever.
          if text.length < 12_000 && text.match?(MONOLOGUE_TOOL_INTENT_RX)
            # Prefer bounce when no concrete shell(...) / tool call is embedded.
            return true unless defined?(Dispatch) && Dispatch.respond_to?(:tool_calls_from_text)
            return true if Dispatch.tool_calls_from_text(text: text).empty?

          end

          # Degenerate repetition ("Wait, let's try…" loop) always incomplete.
          lines = text.lines.map { |l| l.strip.downcase }.reject(&:empty?)
          if lines.length >= 6
            uniq_ratio = lines.uniq.length.to_f / lines.length
            return true if uniq_ratio < 0.35
          end

          false
        rescue StandardError
          false
        end

        private_class_method def self.max_iters
          v = (PWN::Env.dig(:ai, :agent, :max_iters) if defined?(PWN::Env))
          n = v.to_i.positive? ? v.to_i : DEFAULT_MAX_ITERS
          # 0.3 — frontier leakage: live max_iters=80 burns local models.
          # Cap ollama at 25 unless the operator set an explicit lower value.
          n = 75 if local_engine? && n > 75
          # P7 — W3 controller: when this engine is badly overconfident,
          # shrink the tool budget so thrash can't compound on bad plans.
          cal = calibration_state
          n = [n, cal[:max_iters_cap]].min if cal[:overconfident]
          # P17 — when agent_loop budget_exhaustion dominates open mistakes,
          # shrink thrash WITHOUT collapsing long multi-step autonomy.
          # Local (ollama) stays harsh (8). Remote engines keep a multi-step
          # runway (25): the always-8-for-ALL policy starved long-lived goals
          # (only ~5 tool rounds after the hot text-only tail) while scars were
          # still open. incomplete_final? + evidence_enough_to_finalize? still
          # refuse polite handoffs and finish early when evidence is enough.
          # CF / red_team forks stay suppressed while hot.
          if budget_exhaustion_hot?
            hot_cap = local_engine? ? 24 : 75
            n = [n, hot_cap].min
          end
          n
        rescue StandardError
          DEFAULT_MAX_ITERS
        end

        # P7 — read Metrics.calibration for the active engine and decide
        # whether to force plan_first/critic and cap iters.
        # Thresholds: brier > 0.35 OR overconfidence > 0.25 with n >= 8.
        private_class_method def self.calibration_state
          eng = active_engine
          cal = defined?(Metrics) && Metrics.respond_to?(:calibration) ? Metrics.calibration(engine: eng) : { n: 0 }
          n = cal[:n].to_i
          return { overconfident: false, force_plan: false, force_critic: false, max_iters_cap: 75, cal: cal } if n < 24

          brier = cal[:brier].to_f
          over  = cal[:overconfidence].to_f
          # P17 — gate lowered 0.25→0.20: grok lived at 0.242 and never tripped,
          # leaving force_plan off while still thrashing tool budgets.
          bad   = brier > 0.35 || over > 0.20
          # P28 — autonomy: overconfidence must force plan+critic and shrink thrash,
          # but must NOT collapse multi-step remote work to 8 iters (user-visible
          # "stop to confirm next step" / early text-only handoffs). Local models
          # keep the harsh 8; remote engines keep a usable multi-step runway.
          remote_cap = 120
          local_cap  = 24
          cap = if bad
                  (local_engine?(engine: eng) ? local_cap : remote_cap)
                else
                  75
                end
          {
            overconfident: bad,
            force_plan: bad,
            force_critic: bad,
            max_iters_cap: cap,
            cal: cal
          }
        rescue StandardError
          { overconfident: false, force_plan: false, force_critic: false, max_iters_cap: 75 }
        end

        # Local/on-box engines share tight-context scaffolding (plan_first,
        # tool_router, result caps, tool_choice pressure). Both :ollama
        # (native server) and :openwebui (gateway in front of models) count.
        private_class_method def self.local_engine?(opts = {})
          eng = opts.key?(:engine) ? opts[:engine].to_s.downcase.to_sym : active_engine
          %i[ollama openwebui].include?(eng)
        rescue StandardError
          false
        end

        private_class_method def self.active_engine
          e = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s.downcase.to_sym
          e == :'' ? :openai : e
        rescue StandardError
          :openai
        end

        private_class_method def self.agent_flag(opts = {})
          key = opts[:key]
          v = (PWN::Env.dig(:ai, :agent, key) if defined?(PWN::Env))
          v.nil? ? opts[:default] : v
        rescue StandardError
          opts[:default]
        end

        # Record per-tool telemetry AND, when the dispatch failed, fingerprint
        # the failure into PWN::AI::Agent::Mistakes so recurring errors are
        # counted, surfaced in the system prompt, and can be resolved with an
        # explicit fix. Returns { ok:, err:, mistake: } — :mistake carries the
        # PERSISTED entry (with cumulative :count and any prior :fix) so the
        # caller drives cross-session repeat detection, not just per-turn.
        # R5 — close a leftover MDP episode when auto_introspect was skipped
        # or swallowed. No-op once Policy.finish already ran inside introspect.
        private_class_method def self.maybe_finish_policy(opts = {})
          return unless defined?(PWN::AI::Agent::Policy) && Policy.respond_to?(:current_episode)
          return unless Policy.current_episode

          Policy.finish(
            session_id: opts[:session_id],
            score: opts[:score],
            verdict: opts[:verdict],
            proxy_ok: opts.fetch(:proxy_ok, false),
            final: opts[:final],
            ts_state: opts[:ts_state]
          )
        rescue StandardError
          nil
        end

        private_class_method def self.record_metrics(opts = {})
          name    = opts[:name]
          started = opts[:started]
          raw     = opts[:raw].to_s
          # R4 — structured result: :ok = handler didn't raise, :semantic_ok
          # additionally knows grep exit 1 / diff exit 1 / xargs 123 are
          # informational. Metrics records :ok; Mistakes only records
          # !semantic_ok. Kills the phantom 31f1871b8a15 class permanently.
          sem = defined?(Reward) ? Reward.semantic_ok(name: name, raw: raw, args: opts[:args]) : { ok: raw.include?('"success":true'), semantic_ok: raw.include?('"success":true'), err: raw[/"error":"([^"]{1,300})"/, 1] }
          dur = started ? (Time.now - started) : 0.0
          # 1.2 — align Metrics proxy with R4 semantic_ok (handler-ok alone
          # was the reward-signal lie: grep exit 1 looked like 100% success
          # while Mistakes stayed quiet, OR the inverse phantom class).
          Metrics.record(name: name, success: sem[:semantic_ok], duration: dur, error: sem[:err], engine: opts[:engine]) if defined?(Metrics)
          # R5 — live MDP step. Hygiene reward only; terminal credit is judge.
          if defined?(PWN::AI::Agent::Policy) && Policy.respond_to?(:observe_step)
            Policy.observe_step(
              session_id: opts[:session_id],
              action: name,
              ok: sem[:semantic_ok],
              duration: dur,
              engine: opts[:engine],
              ts_state: opts[:ts_state]
            )
          end
          m = nil
          if !sem[:semantic_ok] && defined?(Mistakes) && sem[:shape].to_s != 'invalid_payload' && !raw.include?('extinguished_repeat')
            # E1 — automatic blame attribution: if this tool just tripped a
            # CUSUM changepoint AND extro drift is present, tag the mistake
            # cause: :env_drift so it does NOT count toward [REPEATING].
            cause = attribute_cause(name: name)
            m = Mistakes.record(tool: name, error: sem[:err] || raw[0, 300], args: opts[:args], session_id: opts[:session_id], source: :tool, cause: cause, shape: sem[:shape])
            m = Mistakes.extinguish!(signature: m[:signature], args: opts[:args], shape: sem[:shape]) || m if m && defined?(Mistakes) && Mistakes.respond_to?(:extinguish!)
          end
          { ok: sem[:semantic_ok], err: sem[:err], mistake: m, benign: sem[:benign] }
        rescue StandardError
          { ok: true, err: nil, mistake: nil }
        end

        # E1 — did the environment change under this tool? If Metrics CUSUM
        # tripped for it in the last hour AND Extrospection.drift shows a
        # toolchain/net/repo change, blame the WORLD not the AGENT.
        private_class_method def self.attribute_cause(opts = {})
          return :self unless defined?(Metrics) && Metrics.respond_to?(:changepoints)

          cp = Metrics.changepoints(within_secs: 3_600).find { |c| c[:name] == opts[:name].to_s }
          return :self unless cp
          return :self unless defined?(Extrospection)

          d = Extrospection.drift(live: false)
          Array(d[:changed]).any? { |c| c[:path].to_s.match?(/toolchain|net|repo|host/) } ? :env_drift : :self
        rescue StandardError
          :self
        end

        # Stash the active session_id under PWN::Env[:ai][:session_id] so
        # tool handlers (sessions_current) can discover it without a Pry
        # dependency. PWN::Env is frozen at the top level but [:ai] is a
        # nested mutable Hash on all supported config paths — swallow if not.
        private_class_method def self.expose_current_session(opts = {})
          sid = opts[:session_id]
          return unless sid && defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          ai = PWN::Env[:ai]
          ai[:session_id] = sid if ai.is_a?(Hash) && !ai.frozen?
        rescue StandardError
          nil
        end

        private_class_method def self.append_session(opts = {})
          session_id = opts[:session_id]
          return unless session_id && defined?(PWN::Sessions)

          PWN::Sessions.append(
            session_id: session_id,
            role: opts[:role],
            content: opts[:content]
          )
        rescue StandardError
          nil
        end

        # Repeat circuit-breaker. `count` is max(per-turn, persistent) so a
        # signature that already failed in a PREVIOUS session trips the guard
        # on its FIRST recurrence here — the agent does not get to burn the
        # iteration budget re-learning a lesson it already recorded.
        private_class_method def self.guard_repeated_failure(opts = {})
          count  = opts[:count].to_i
          result = opts[:result].to_s
          hint   = opts[:hint].to_s
          thresh = defined?(Mistakes) ? Mistakes::REPEAT_THRESHOLD : 3
          result = "#{result}\n#{hint}" unless hint.empty?
          return result if count < thresh

          if defined?(Mistakes) && Mistakes.respond_to?(:extinguish!)
            sig = opts[:mistake].is_a?(Hash) ? opts[:mistake][:signature] : nil
            Mistakes.extinguish!(signature: sig, args: opts[:args], shape: opts[:shape], force: true) if sig
          end
          Thread.current[:pwn_extinguished] ||= {}
          Thread.current[:pwn_extinguished][opts[:name].to_s] = true

          guard = "[pwn-ai/mistakes] EXTINGUISHED / REPEATED FAILURE — this #{opts[:name]} failure signature has " \
                  "occurred #{count}× (across sessions). DO NOT retry it verbatim. Apply the " \
                  'KNOWN FIX if present, pick a different tool, or explain the blocker. ' \
                  'explain why it cannot succeed. Once a working alternative is found, call ' \
                  'mistakes_resolve(signature:, fix:) so future runs skip straight to it.'
          "#{guard}\n#{result}"
        end

        # Plan-then-act pre-pass: force the (usually local) model to
        # externalise a numbered tool plan BEFORE it may call any tool. The
        # plan rides along as an assistant message so every subsequent
        # iteration attends over it — cheap chain-of-thought scaffolding
        # without leaking to the user.
        private_class_method def self.plan_first(opts = {})
          messages = opts[:messages]
          # P17 — under budget_exhaustion_hot the plan must be ultra-short:
          # red_team_plan is a nested agent loop and was the #1 amplifier of
          # iteration-budget exhaustion on this host (together with CF).
          hot = begin
            budget_exhaustion_hot?
          rescue StandardError
            false
          end
          plan_prompt = if hot && local_engine?
                          # Local hot: ultra-short plan — finish-under-8 is the skill gap.
                          'Before acting: write AT MOST 3 numbered tool calls (name + key args) that finish the ask. Prefer fewer. LAST line: "p(success)=<0.0-1.0>". Reply ONLY with the plan + that line — no tools, no prose.'
                        elsif hot
                          # Remote hot: efficient FULL plan — do not cut multi-step goals to 3 steps.
                          'Before acting: (1) list the exact tool calls (name + key args) that FULLY finish the user goal, in order — prefer the shortest plan that still completes every step, do not stop at a checkpoint for confirmation; (2) on the LAST line write "p(success)=<0.0-1.0>". Reply ONLY with the numbered plan + that line — do NOT call any tool yet.'
                        else
                          'Before acting: (1) list the exact tool calls (name + key args) that FULLY finish the user goal, in order — do not stop at a checkpoint for confirmation; (2) on the LAST line write "p(success)=<0.0-1.0>". Reply ONLY with the numbered plan + that line — do NOT call any tool yet.'
                        end
          plan_msg = call_engine(
            messages: messages + [{ role: 'user', content: plan_prompt }],
            tools: nil
          )
          return nil unless plan_msg && !plan_msg[:content].to_s.strip.empty?

          plan = plan_msg[:content].to_s.strip
          messages << { role: 'assistant', content: "PLAN:\n#{plan}" }
          # S4 — adversarial plan review grounded in THIS host's telemetry.
          # P17 — never fork red_team when budget fingerprints dominate: it is
          # another mini agent loop and compounds iteration-budget exhaustion.
          rt = nil
          if defined?(Curriculum) && !hot
            rt = Curriculum.red_team_plan(request: opts[:request], plan: plan)
            messages << { role: 'user', content: rt } if rt
          end
          # P2 — unify TaskSummarizer plan object with surviving outline so the
          # task line and adversarial/plan_first plan are one thing. Index-only;
          # credit stays in Reward. Optional: only when ts_state is live.
          if defined?(TaskSummarizer) && opts[:ts_state].is_a?(Hash)
            outline = [plan.to_s, rt.to_s].reject { |s| s.to_s.strip.empty? }.join("\n")
            begin
              TaskSummarizer.unify_plan!(
                state: opts[:ts_state],
                outline: outline,
                source: rt ? :red_team : :plan_first
              )
            rescue StandardError => e
              warn "[pwn-ai/loop] unify_plan! swallowed: #{e.class}: #{e.message}"
            end
          end
          # W3/P22 — extract predicted p(success) for calibration tracking.
          # Accept p(success)=0.7 | p(success) = .7 | confidence=0.7 on last lines.
          predicted = plan[/p\(\s*success\s*\)\s*=\s*([01]?(?:\.\d+)?)/i, 1]&.to_f
          predicted = plan[/\bconfidence\s*=\s*([01]?(?:\.\d+)?)/i, 1]&.to_f if predicted.nil?
          predicted = predicted.clamp(0.0, 1.0) if predicted
          # Stash so auto_introspect / recover can always see it even if the
          # return value is dropped by a caller rescue.
          Thread.current[:pwn_plan_predicted] = predicted
          predicted
        rescue StandardError => e
          warn "[pwn-ai/loop] plan_first swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Swarm escalation circuit-breaker: when a local model has burned
        # ≥ ESCALATE_AFTER_FAILS distinct failures this turn, ask a frontier
        # persona for a 3-line corrective hint and inject it as a synthetic
        # tool result. Every escalation is recorded as a Mistake so
        # export_finetune can later teach the LoRA to NOT need it.
        @escalate_warned = false
        private_class_method def self.escalate(opts = {})
          request    = opts[:request]
          turn_fails = opts[:turn_fails]
          persona    = agent_flag(key: :escalation_persona)
          # Vault files pre-dating PR-A leave escalation_persona nil; if the
          # default "escalator" persona exists on disk, use it automatically.
          persona = :escalator if (persona.nil? || persona.to_s.empty?) && defined?(Swarm) && Swarm.personas.key?(:escalator)
          unless persona && defined?(Swarm)
            unless @escalate_warned
              warn '[pwn-ai/loop] escalation_persona unset or Swarm unavailable — local thrash will burn iters without a frontier hint. Set PWN::Env[:ai][:agent][:escalation_persona] (default: escalator).'
              @escalate_warned = true
            end
            return nil
          end
          unless Swarm.personas.key?(persona.to_sym)
            unless @escalate_warned
              warn "[pwn-ai/loop] escalation_persona=#{persona.inspect} not in ~/.pwn/agents.yml — define it or set nil. ESCALATE_AFTER_FAILS is a no-op."
              @escalate_warned = true
            end
            return nil
          end

          summary = turn_fails.map { |k, v| "#{k}: #{v}×" }.join(', ')
          hint = Swarm.ask(
            name: persona.to_s,
            request: "Local agent is stuck on: #{request}\nFailed attempts: #{summary}\n" \
                     'Give a 3-line corrective hint (which tool, which args, why). Reply with the hint ONLY.'
          )
          reply = hint.is_a?(Hash) ? hint[:reply].to_s : hint.to_s
          Mistakes.record(tool: 'escalation', error: "local stuck after #{turn_fails.values.sum} fails; frontier hint requested", session_id: opts[:session_id], source: :loop) if defined?(Mistakes)
          reply.strip.empty? ? nil : "[pwn-ai/escalation] frontier hint (#{persona}):\n#{reply.strip}"
        rescue StandardError => e
          warn "[pwn-ai/loop] escalate swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Publish the last engine response's token usage into
        # PWN::Env[:ai][<engine>][:response_history] so
        # PWN::Plugins::REPL.refresh_ps1_proc can render the live
        # context-window fill indicator (e.g. "12K:200K"). The legacy
        # regex-ReAct path in REPL wrote this itself; the native tool
        # loop is the default path now and must do the same or the PS1
        # `used_tokens` stays pinned at 0.
        private_class_method def self.publish_usage(opts = {})
          resp   = opts[:response]
          engine = opts[:engine]
          return unless resp.is_a?(Hash) && defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          eng_env = PWN::Env.dig(:ai, engine)
          return unless eng_env.is_a?(Hash) && !eng_env.frozen?

          usage = resp[:usage]
          # Ollama native /api/chat returns prompt_eval_count / eval_count
          # instead of an OpenAI-shape :usage hash — normalise here so the
          # PS1 dig(:response_history, :usage, :total_tokens) works uniformly.
          if !usage.is_a?(Hash) && (resp[:prompt_eval_count] || resp[:eval_count])
            pt = resp[:prompt_eval_count].to_i
            ct = resp[:eval_count].to_i
            usage = { prompt_tokens: pt, completion_tokens: ct, total_tokens: pt + ct }
          end
          return unless usage.is_a?(Hash)

          total = usage[:total_tokens] ||
                  ((usage[:prompt_tokens] || usage[:input_tokens]).to_i +
                   (usage[:completion_tokens] || usage[:output_tokens]).to_i)

          rh = eng_env[:response_history].is_a?(Hash) ? eng_env[:response_history] : {}
          rh[:id]    = resp[:id]    if resp[:id]
          rh[:model] = resp[:model] if resp[:model]
          rh[:usage] = usage.merge(total_tokens: total.to_i)
          eng_env[:response_history] = rh
        rescue StandardError => e
          warn "[pwn-ai/loop] publish_usage swallowed: #{e.class}: #{e.message}"
        end

        # Ollama / Open WebUI proxied /ollama/api/chat expect function.arguments
        # as a JSON *object* (map), not a JSON-encoded string. Loop.normalize_llm
        # and openai_wire_tool_call stringify for OpenAI/xAI; replaying that
        # history into local engines produces HTTP 400:
        #   {"detail":"Value looks like object, but can't find closing '}' symbol"}
        # because the gateway parses the string as if it were raw object text.
        private_class_method def self.parse_tool_arguments(opts = {})
          raw = opts[:arguments]
          case raw
          when Hash, Array
            # Object form (Hash) is Ollama-native; Array is rare but keep as-is.
            raw
          when nil
            {}
          when String
            s = raw.strip
            return {} if s.empty?

            begin
              parsed = JSON.parse(s, symbolize_names: true)
              return parsed if parsed.is_a?(Hash) || parsed.is_a?(Array)
            rescue JSON::ParserError
              # fall through
            end
            # Non-JSON bare string — wrap so the schema still gets an object.
            { value: s }
          else
            { value: raw.to_s }
          end
        end

        private_class_method def self.ollama_wire_tool_call(opts = {})
          tc = opts[:tool_call]
          return nil unless tc.is_a?(Hash)

          fn = tc[:function] || tc['function'] || {}
          name = fn[:name] || fn['name'] || tc[:name] || tc['name']
          args = fn[:arguments] || fn['arguments'] || tc[:arguments] || tc['arguments']
          {
            id: (tc[:id] || tc['id'] || "call_#{SecureRandom.hex(4)}").to_s,
            type: (tc[:type] || tc['type'] || 'function').to_s,
            function: {
              name: name.to_s,
              arguments: parse_tool_arguments(arguments: args)
            }
          }
        end

        # Supported Method Parameters::
        # wire = PWN::AI::Agent::Loop.ollama_wire_messages(
        #   messages: 'required - in-memory OpenAI-ish messages (may have String args)'
        # )
        #
        # Returns a deep-copied array safe for Ollama / Open WebUI ollama/api/chat:
        # - parses JSON-string function.arguments into Hash/Array objects
        # - coerces nil assistant content to '' when tool_calls present
        #   (Open WebUI GenerateChatCompletionForm rejects content:null alone)
        # - drops _native_content / _text_tool_coerced / thinking private keys
        # - stringifies Hash/Array message content (tool results) to JSON text

        public_class_method def self.ollama_wire_messages(opts = {})
          messages = opts[:messages]
          Array(messages).filter_map do |m|
            next unless m.is_a?(Hash)

            role = (m[:role] || m['role']).to_s
            out = { role: role }

            tcs = m[:tool_calls] || m['tool_calls']
            wired_tcs = nil
            if tcs
              wired_tcs = Array(tcs).filter_map { |tc| ollama_wire_tool_call(tool_call: tc) }
              out[:tool_calls] = wired_tcs unless wired_tcs.empty?
            end

            if m.key?(:content) || m.key?('content')
              content = m.key?(:content) ? m[:content] : m['content']
              out[:content] = case content
                              when nil
                                # Open WebUI: null content without tool_calls 400s;
                                # with tool_calls prefer "" over null.
                                wired_tcs && !wired_tcs.empty? ? '' : nil
                              when String then content
                              when Hash, Array then JSON.generate(content)
                              else content.to_s
                              end
            elsif wired_tcs && !wired_tcs.empty?
              out[:content] = ''
            end

            name = m[:name] || m['name']
            out[:name] = name.to_s if name && !name.to_s.empty?

            tcid = m[:tool_call_id] || m['tool_call_id']
            out[:tool_call_id] = tcid.to_s if tcid && !tcid.to_s.empty?

            out
          end
        end

        # OpenAI-compatible wire format (xAI Grok / OpenAI chat.completions):
        # function.arguments MUST be a JSON string, not a map; message.content
        # MUST be a string (or null). Internal Hash arguments from Ollama or
        # Dispatch.tool_calls_from_text caused:
        #   422 Unprocessable Entity: messages[N]: invalid type: map, expected a string
        private_class_method def self.stringify_tool_arguments(opts = {})
          raw = opts[:arguments]
          case raw
          when String then raw.empty? ? '{}' : raw
          when Hash, Array then JSON.generate(raw)
          when nil then '{}'
          else
            s = raw.to_s
            s.empty? ? '{}' : s
          end
        end

        private_class_method def self.openai_wire_tool_call(opts = {})
          tc = opts[:tool_call]
          return nil unless tc.is_a?(Hash)

          fn = tc[:function] || tc['function'] || {}
          name = fn[:name] || fn['name'] || tc[:name] || tc['name']
          args = fn[:arguments] || fn['arguments'] || tc[:arguments] || tc['arguments']
          {
            id: (tc[:id] || tc['id'] || "call_#{SecureRandom.hex(4)}").to_s,
            type: (tc[:type] || tc['type'] || 'function').to_s,
            function: {
              name: name.to_s,
              arguments: stringify_tool_arguments(arguments: args)
            }
          }
        end

        # Supported Method Parameters::
        # wire = PWN::AI::Agent::Loop.openai_wire_messages(
        #   messages: 'required - in-memory OpenAI-ish messages (may have Hash args / internal keys)'
        # )
        #
        # Returns a deep-copied array safe for OpenAI / xAI chat.completions:
        # - drops _native_content / _text_tool_coerced / thinking private keys
        # - stringifies function.arguments maps
        # - coerces Hash/non-string content to JSON/string (nil kept for assistant tool turns)

        public_class_method def self.openai_wire_messages(opts = {})
          messages = opts[:messages]
          Array(messages).filter_map do |m|
            next unless m.is_a?(Hash)

            role = (m[:role] || m['role']).to_s
            out = { role: role }

            if m.key?(:content) || m.key?('content')
              content = m.key?(:content) ? m[:content] : m['content']
              out[:content] = case content
                              when nil then nil
                              when String then content
                              when Hash, Array then JSON.generate(content)
                              else content.to_s
                              end
            end

            name = m[:name] || m['name']
            out[:name] = name.to_s if name && !name.to_s.empty?

            tcid = m[:tool_call_id] || m['tool_call_id']
            out[:tool_call_id] = tcid.to_s if tcid && !tcid.to_s.empty?

            tcs = m[:tool_calls] || m['tool_calls']
            if tcs
              wired = Array(tcs).filter_map { |tc| openai_wire_tool_call(tool_call: tc) }
              out[:tool_calls] = wired unless wired.empty?
            end

            out
          end
        end

        # Supported Method Parameters::
        # msg = PWN::AI::Agent::Loop.normalize_llm(
        #   response: 'required - chat_with_tools response Hash from any provider'
        # )

        private_class_method def self.normalize_llm(opts = {})
          resp = opts[:response]
          return nil unless resp.is_a?(Hash)

          msg = resp.dig(:choices, 0, :message) || resp[:assistant_message]
          return nil unless msg

          content = msg[:content]
          tool_calls = Array(msg[:tool_calls])
          # Local/thinking models (Ollama Qwen3, DeepSeek-R1, etc.) sometimes
          # return only :thinking with empty :content and no tool_calls. Promote
          # thinking so the agent does not print a blank final answer.
          if content.to_s.strip.empty? && tool_calls.empty?
            thinking = msg[:thinking].to_s
            content = thinking unless thinking.strip.empty?
          end

          out = {
            role: 'assistant',
            content: content,
            tool_calls: tool_calls.map do |tc|
              {
                id: tc[:id],
                type: 'function',
                function: {
                  name: tc.dig(:function, :name) || tc[:name],
                  arguments: stringify_tool_arguments(
                    arguments: tc.dig(:function, :arguments) || tc[:arguments]
                  )
                }
              }
            end
          }
          # Preserve provider-native content blocks so chat can round-trip
          # them exactly on the next iteration (e.g. Anthropic requires the
          # original tool_use block to precede a tool_result).
          out[:_native_content] = msg[:_native_content] if msg[:_native_content]
          out[:thinking] = msg[:thinking] if msg[:thinking]
          # Local/abliterated models sometimes emit shell(...) as plain content
          # with empty tool_calls. Coerce registered call-shaped text into
          # structured tool_calls so Loop dispatches instead of FINAL-answering.
          if out[:tool_calls].empty? && defined?(Dispatch) && Dispatch.respond_to?(:tool_calls_from_text)
            coerced = Dispatch.tool_calls_from_text(text: out[:content].to_s)
            if coerced.any?
              out[:tool_calls] = coerced.map { |tc| openai_wire_tool_call(tool_call: tc) }
              out[:content] = nil
              out[:_text_tool_coerced] = true
            end
          end
          out
        end

        # Supported Method Parameters::
        # msg = PWN::AI::Agent::Loop.call_engine(
        #   messages: 'required - OpenAI-format messages array',
        #   tools: 'optional - OpenAI tools array'
        # )
        #
        # Returns a normalised assistant message hash:
        #   { role: 'assistant', content: String|nil,
        #     tool_calls: [ {id:, type:'function', function:{name:, arguments:}} ],
        #     _native_content: <provider raw>  (when adapter needs round-trip) }

        private_class_method def self.call_engine(opts = {})
          messages = opts[:messages]
          tools = opts[:tools]

          engine = active_engine
          mod_name = ENGINE_MODS[engine]
          raise "ERROR: Unsupported AI engine for agent loop: #{engine}" unless mod_name

          mod = Object.const_get(mod_name)
          if mod.respond_to?(:chat_with_tools)
            # xAI/OpenAI reject Hash function.arguments / Hash content (422 map→string).
            # Ollama / Open WebUI reject *string* function.arguments (HTTP 400
            # "can't find closing '}' symbol") — opposite of OpenAI wire form.
            wire_msgs = if %i[grok openai].include?(engine)
                          openai_wire_messages(messages: messages)
                        elsif local_engine?(engine: engine)
                          ollama_wire_messages(messages: messages)
                        else
                          messages
                        end
            cwt_opts = {
              messages: wire_msgs,
              tools: tools,
              spinner: true
            }
            # Ollama + abliterated / weak chat-templates often ignore tools: and
            # answer in prose (or print shell(...) as text). Force native
            # tool_calls until at least one tool result is already in history;
            # after that, auto so the model can emit a real final answer.
            # Respect explicit PWN::Env[:ai][:ollama][:tool_choice] override.
            if local_engine?(engine: engine) && tools && !tools.empty?
              env_tc = begin
                PWN::Env.dig(:ai, engine, :tool_choice)
              rescue StandardError
                nil
              end
              if env_tc && !env_tc.to_s.empty?
                cwt_opts[:tool_choice] = env_tc
              else
                # After the first tool result, auto so the model can emit a
                # real final. English tasks do not keep tool_choice=required.
                has_tool_result = Array(messages).any? { |m| m[:role].to_s == 'tool' }
                last_asst = Array(messages).reverse.find { |m| m[:role].to_s == 'assistant' }
                last_txt = last_asst.is_a?(Hash) ? last_asst[:content].to_s : ''
                still_acting = !has_tool_result || incomplete_final?(text: last_txt, last_iter: false)
                cwt_opts[:tool_choice] = has_tool_result && !still_acting ? 'auto' : 'required'
              end
            end
            response = mod.chat_with_tools(cwt_opts)
            publish_usage(response: response, engine: engine)
            normalize_llm(response: response)
          else
            degrade_text_only(mod: mod, messages: messages)
          end
        end

        # 3.1 — sliding-window history compaction for local models.
        # Keep: system, original user, PLAN assistant (if any), last K tool
        # pairs (assistant+tool), and the most recent assistant. Stale tool
        # bodies are truncated to history_tool_max_chars.
        private_class_method def self.compact_history!(opts = {})
          messages = opts[:messages]
          return messages unless messages.is_a?(Array) && messages.length > 12

          keep_pairs = (agent_flag(key: :history_keep_tool_pairs, default: 6) || 6).to_i
          max_chars  = (agent_flag(key: :history_tool_max_chars, default: 2_000) || 2_000).to_i

          head = []
          rest = messages.dup
          # always keep leading system + first user + optional PLAN
          while rest.any? && %w[system user].include?(rest.first[:role].to_s)
            head << rest.shift
            break if head.any? { |m| m[:role].to_s == 'user' }
          end
          head << rest.shift if rest.any? && rest.first[:role].to_s == 'assistant' && rest.first[:content].to_s.start_with?('PLAN:')

          # find indices of tool messages in rest; keep only last keep_pairs tool groups
          tool_idxs = rest.each_index.select { |i| rest[i][:role].to_s == 'tool' }
          drop_before = tool_idxs.length > keep_pairs ? tool_idxs[-keep_pairs] : 0
          # include the assistant tool_call message immediately before first kept tool
          start = drop_before
          start -= 1 if start.positive? && rest[start - 1] && rest[start - 1][:role].to_s == 'assistant'
          kept = rest[start..] || []
          kept.each do |m|
            next unless m[:role].to_s == 'tool' && m[:content].to_s.length > max_chars

            m[:content] = "#{m[:content].to_s[0, max_chars]}…[compacted]"
          end
          messages.replace(head + kept)
          messages
        rescue StandardError => e
          warn "[pwn-ai/loop] compact_history swallowed: #{e.class}: #{e.message}"
          opts[:messages]
        end

        # 3.2 — local models cannot afford auto_introspect (judge+prm+critic+
        # sentinel+extro) on every success. Default :failure_only when local.
        private_class_method def self.should_auto_introspect?(opts = {})
          kind = (opts[:kind] || Thread.current[:pwn_request_kind]).to_s.to_sym
          intent = (opts[:intent] || Thread.current[:pwn_request_intent]).to_s.to_sym
          fails = opts[:turn_fails].is_a?(Hash) ? opts[:turn_fails].values.sum : 0
          # Cheap answers already returned user-visible text. The post-answer
          # critic + 12s ORM printed ERROR: Timed out reading data from server
          # after greetings / takes / questions.
          return false if %i[greeting howto recall].include?(intent)
          return false if kind == :statement
          return false if kind == :question && fails.zero?

          return true unless opts[:local]

          policy = agent_flag(key: :local_introspect, default: :failure_only).to_s.to_sym
          case policy
          when :always then true
          when :every_n
            n = (agent_flag(key: :introspect_every_n, default: 3) || 3).to_i
            n = 3 if n < 1
            (opts[:iter].to_i % n).zero?
          else # :failure_only
            opts[:turn_fails].is_a?(Hash) && opts[:turn_fails].values.sum.positive?
          end
        rescue StandardError
          true
        end

        # Push a name='task' event through the REPL on_tool UI
        # (repl.rb) so arg_preview is the plain-English executive brief.
        # result is ALWAYS '' for task lines — displaying a task must not
        # also print a result row (one-to-many: one task, many tools).
        private_class_method def self.emit_task_summary(opts = {})
          line = opts[:line]
          return if line.nil? || line.to_s.strip.empty?

          on_tool = opts[:on_tool]
          return unless on_tool

          # name MUST be 'task'; third arg MUST be empty (no result noise).
          # Only the REPL on_tool path prints: [ ts → pwn-ai → task ] <brief>
          # Do not also warn with a redundant [pwn-ai/task] prefix.
          on_tool.call('task', line.to_s, '')
        rescue StandardError
          nil
        end

        # Push active English task into model messages when plan_idx changes.
        # Uses TaskSummarizer.active_task_prompt (full plan_context on first
        # force, compact focus thereafter). No-ops when already injected.
        private_class_method def self.inject_task_focus!(opts = {})
          state = opts[:state]
          messages = opts[:messages]
          return nil unless state.is_a?(Hash) && messages.is_a?(Array)
          return nil unless defined?(TaskSummarizer) && TaskSummarizer.enabled?
          return nil unless TaskSummarizer.plan_open?(state: state, messages: messages)

          req = opts[:request]
          req = state[:original_request] || state[:request] if req.to_s.strip.empty? && state.is_a?(Hash)
          text =
            (TaskSummarizer.active_task_prompt(state: state, force: opts[:force], request: req) if TaskSummarizer.respond_to?(:active_task_prompt))
          return nil if text.to_s.strip.empty?

          messages << { role: 'user', content: text }
          text
        rescue StandardError => e
          warn "[pwn-ai/loop] inject_task_focus! swallowed: #{e.class}: #{e.message}"
          nil
        end

        # On user-request submit: break the goal into tangible tasks and
        # emit the FULL plan on the pwn-ai task line (no truncation).
        private_class_method def self.task_summary_plan!(opts = {})
          state = opts[:state]
          return nil unless state && defined?(TaskSummarizer) && TaskSummarizer.enabled?

          line = TaskSummarizer.emit_plan!(state: state, request: opts[:request])
          emit_task_summary(line: line, on_tool: opts[:on_tool]) if line
          line
        rescue StandardError
          nil
        end

        # Pre-dispatch: one high-level brief for the whole upcoming tool
        # collection (pwn-ai → task is one-to-many with pwn-ai → <tool>).
        # Prefer opts[:tools] = [{name:, args:}, ...]; falls back to single name.
        private_class_method def self.task_summary_about_to!(opts = {})
          state = opts[:state]
          return nil unless state && defined?(TaskSummarizer) && TaskSummarizer.enabled?

          line = TaskSummarizer.about_to(
            name: opts[:name],
            args: opts[:args],
            state: state,
            request: opts[:request],
            tools: opts[:tools]
          )
          # about_to returns nil when the brief is a duplicate of the last one
          emit_task_summary(line: line, on_tool: opts[:on_tool]) if line
          line
        rescue StandardError
          nil
        end

        # Track completed tools for optional verbose/flush briefs.
        # Never attaches tool results to a task line.
        private_class_method def self.task_summary_record!(opts = {})
          state = opts[:state]
          return nil unless state && defined?(TaskSummarizer)

          line = TaskSummarizer.record!(
            state: state,
            name: opts[:name],
            args: opts[:args],
            result: opts[:result]
          )
          # record! is silent by default; only verbose progress returns a line
          emit_task_summary(line: line, on_tool: opts[:on_tool]) if line
          line
        rescue StandardError
          nil
        end

        private_class_method def self.task_summary_flush!(opts = {})
          state = opts[:state]
          return nil unless state && defined?(TaskSummarizer)

          line = TaskSummarizer.flush!(state: state)
          # Closing brief only — still no result payload on the task row
          emit_task_summary(line: line, on_tool: opts[:on_tool]) if line
          line
        rescue StandardError
          nil
        end

        # Request intent for routing (how-to vs act/recon vs pure recall/greeting).
        # Local models thrash when pure explanation/recall/greeting asks are
        # force-planned into multi-step host probes or multi-tool session archaeology.
        # :howto → answer with explanation only (no plan_first / no live recon).
        # :recall → prior-turn / vague memory cue; cheap path only.
        # :greeting → short hello / light smalltalk; deterministic ack, no tools.
        # :recon_act → live discovery; requires explicit authorization language.
        # :act → general agent work with tools.
        HOWTO_RX = /
          \b(
            how\s+to|how\s+do\s+i|how\s+can\s+i|how\s+would\s+i|how\s+does\s+one|
            what\s+is\s+the\s+(?:syntax|command|usage|flag|option)|
            explain\s+how|show\s+me\s+how|examples?\s+of\s+using|
            manual\s+for|usage\s+of|syntax\s+for|man\s+page
          )\b
        /ix

        # Pure prior-turn recall — must never enter plan_first / multi-tool loops.
        # Covers both "what did I just say?" (user) and "how did you respond?"
        # / "what did you just say?" (assistant) so last-turn injection is used.
        RECALL_RX = /
          \A\s*(
            what\s+did\s+i\s+(just\s+)?say\??|
            what\s+did\s+i\s+(just\s+)?(?:ask|type|write|request)\??|
            what\s+was\s+my\s+last\s+(?:request|message|question|prompt|turn)\??|
            what\s+was\s+(?:the\s+)?(?:previous|prior|last)\s+(?:thing\s+i\s+said|request|message|turn)\??|
            remind\s+me\s+what\s+i\s+(?:just\s+)?(?:said|asked)\??|
            repeat\s+(?:my\s+)?(?:last|previous)\s+(?:request|message)\??|
            say\s+that\s+again\??|
            recollection\s+test\??|
            memory\s+recall\s+test\??|
            how\s+did\s+you\s+respond(?:\s+to\s+what\s+i\s+(?:just\s+)?(?:said|asked))?\??|
            how\s+did\s+you\s+(?:just\s+)?(?:answer|reply)(?:\s+to\s+(?:me|that|my\s+last))?\??|
            what\s+(?:was|is)\s+your\s+(?:last|previous|prior)\s+(?:answer|response|reply)\??|
            what\s+did\s+you\s+(?:just\s+)?(?:say|answer|reply|respond)\??|
            remind\s+me\s+what\s+you\s+(?:just\s+)?(?:said|answered|replied)\??|
            repeat\s+your\s+(?:last|previous)\s+(?:answer|response|reply)\??
          )\s*\z
        /ix

        # Broader "use your memory / prior context" cues. Still cheap: inject
        # last turn + at most one memory_recall; never multi-step plans.
        VAGUE_MEMORY_RX = /
          \b(
            what\s+did\s+i\s+(just\s+)?(?:say|ask|type|request)|
            what\s+was\s+my\s+last|
            how\s+did\s+you\s+respond|
            what\s+did\s+you\s+(?:just\s+)?(?:say|answer|reply|respond)|
            what\s+(?:was|is)\s+your\s+(?:last|previous|prior)\s+(?:answer|response|reply)|
            (?:without\s+looking\s+up).{0,40}(?:session|discussing|talking)|
            (?:from\s+)?(?:memory|context|earlier|previously|prior\s+turn)|
            (?:do\s+you\s+)?remember\s+what\s+(?:i|you)|
            recall\s+(?:what|my|your|the\s+last)|
            last\s+thing\s+(?:i|you)\s+said
          )\b
        /ix

        # Pure greeting / light smalltalk — never full :act tool loop.
        # Anchored short forms only so "hi, please scan X" stays :act/:recon_act.
        # Do NOT echo weather or invent social filler; answer_greeting is fixed.
        GREETING_RX = /
          \A\s*(
            (?:hi|hello|howdy|hey|yo|sup|hiya|greetings)(?:\s*[.!?]*)?
            (?:\s*,?\s*(?:there|all|folks|team|everyone|y'?all))?
            |
            good\s+(?:morning|afternoon|evening|day|night)(?:\s*[.!?]*)?
            |
            (?:hi|hello|howdy|hey)(?:\s*[.!?*,]*)?\s+
            (?:it'?s|its|it\s+is)\s+
            (?:cloudy|sunny|rainy|raining|foggy|windy|stormy|nice|cold|hot|warm|
               beautiful|gloomy|overcast|clear|chilly|humid|snow(?:ing|y)?)
            (?:\s+out(?:\s+there)?)?(?:\s*[.!?]*)?
            |
            (?:hi|hello|howdy|hey)(?:\s*[.!?*,]*)?\s+
            (?:the\s+weather\s+is\s+\w+|what'?s\s+up|how\s+are\s+you|
               how'?s\s+it\s+going|how\s+goes\s+it)
            (?:\s*[.!?]*)?
          )\s*\z
        /ix

        LIVE_RECON_RX = /
          \b(
            (?:find|discover|enumerate|scan|sweep|probe|map)\s+
            (?:live\s+)?(?:hosts?|ips?|targets?|subnet|network|range)|
            live\s+hosts?\s+(?:can\s+you\s+)?find|
            what\s+live\s+hosts|
            ping\s+sweep\s+(?:of\s+)?(?:this|the|my)\s+
            |(?:run|do|perform)\s+(?:a\s+)?(?:ping\s+)?sweep
            |scan\s+(?:this|the|my)\s+(?:subnet|network|lan|range)
          )\b
        /ix

        AUTH_SCOPE_RX = /
          \b(
            (?:in[-\s]?scope|authorized|authorised|engagement|written\s+permission|
               bug\s*bounty|explicit(?:ly)?\s+allowed|lab\s+only|my\s+lab|
               roe\b|rules?\s+of\s+engagement|i\s+own\s+this|owned\s+by\s+me|
               permission\s+to\s+(?:scan|test|probe)|scope:\s*\S+)
          )\b
        /ix

        public_class_method def self.request_intent(opts = {})
          req = opts[:request].to_s
          return :empty if req.strip.empty?

          # Pure greeting / weather smalltalk before how-to/recon/act.
          # Deterministic short-circuit — never freeform model weather echo.
          return :greeting if req.match?(GREETING_RX)

          # Pure prior-turn recall before how-to/recon (short, decisive).
          return :recall if req.match?(RECALL_RX)

          # Vague memory cues that are still "about the prior turn" and not
          # general work ("remember what we decided about nmap and implement it"
          # stays :act because it pairs memory with a doing verb outside the cue).
          if req.match?(VAGUE_MEMORY_RX) && !req.match?(HOWTO_RX) && !req.match?(LIVE_RECON_RX)
            doing = req.match?(
              /\b(implement|fix|patch|refactor|run|execute|scan|write|edit|
                  change|deploy|install|build|compile|commit|push)\b/ix
            )
            return :recall unless doing
          end

          # Live-action recon takes precedence over bare "how to" when both appear
          # only if the user clearly asks the agent to do the sweep here.
          live = req.match?(LIVE_RECON_RX) && req.match?(
            /\b(can\s+you|could\s+you|please|go\s+ahead|now|on\s+this\s+host|
                this\s+subnet|this\s+network|find\s+(?:for\s+me|me)|discover)\b/ix
          )
          return :recon_act if live || (req.match?(LIVE_RECON_RX) && !req.match?(HOWTO_RX))
          return :howto if req.match?(HOWTO_RX)
          # Interrogative documentation without "how to"
          if req.match?(/\b(what\s+(?:flags?|options?|switches?)|usage|syntax)\b/i) &&
             !req.match?(/\b(run|execute|scan|find|discover)\b/i)
            return :howto
          end

          :act
        rescue StandardError
          :act
        end

        # Top-level request kind for task planning (statement | question | autonomous_goal).
        # Single source of truth: TaskSummarizer.request_kind (LLM + heuristics).
        # Mirrors intent/heuristics only when TaskSummarizer is unavailable.
        #
        # Supported Method Parameters::
        # kind = PWN::AI::Agent::Loop.request_kind(
        #   request: 'required - user text',
        #   kind: 'optional - precomputed',
        #   llm_kind: 'optional - injected LLM label',
        #   heuristic_only: 'optional - skip LLM'
        # )
        public_class_method def self.request_kind(opts = {})
          req = opts[:request].to_s
          if defined?(TaskSummarizer) && TaskSummarizer.respond_to?(:request_kind)
            return TaskSummarizer.request_kind(
              request: req,
              kind: opts[:kind],
              llm_kind: opts[:llm_kind],
              heuristic_only: opts[:heuristic_only]
            )
          end

          case request_intent(request: req)
          when :greeting, :empty
            :statement
          when :howto, :recall
            :question
          when :recon_act
            :autonomous_goal
          else
            # :act — distinguish bare questions from work the agent must do.
            # Host-local facts need tools → autonomous_goal.
            if defined?(TaskSummarizer) && TaskSummarizer.const_defined?(:NEEDS_LOCAL_EVIDENCE_RX)
              return :autonomous_goal if req.match?(TaskSummarizer::NEEDS_LOCAL_EVIDENCE_RX)
            elsif req.match?(/\b(?:hostname|whoami|\bcwd\b|\bpwd\b|my\s+ip)\b/i)
              return :autonomous_goal
            end
            return :question if req.match?(/\?\s*\z/) && !req.match?(
              /\b(please|implement|fix|patch|refactor|run|scan|find|write|change)\b/i
            )
            return :question if req.match?(/\A\s*(?:what|why|when|where|who|which|how)\b/i) &&
                                !req.match?(/\b(please|implement|fix|patch|run|scan)\b/i)

            :autonomous_goal
          end
        rescue StandardError
          :autonomous_goal
        end

        public_class_method def self.recon_authorized?(opts = {})
          req = opts[:request].to_s
          return true if req.match?(AUTH_SCOPE_RX)

          # Explicit engage flag from operator / REPL
          v = (PWN::Env.dig(:ai, :agent, :recon_authorized) if defined?(PWN::Env))
          return true if v == true || v.to_s =~ /\A(1|true|yes|on)\z/i

          false
        rescue StandardError
          false
        end

        # Pure how-to: one text-only chat (no tools, no plan_first, no task recon).
        # Deterministic greeting ack — no LLM, no tools, never mirror weather.

        # Deterministic ack for general statements — no tools, no multi-step plan.
        private_class_method def self.answer_statement(opts = {})
          request = opts[:request].to_s
          session_id = opts[:session_id]
          system_role_content = opts[:system_role_content].to_s
          engine = active_engine
          mod_name = ENGINE_MODS[engine]
          raise "ERROR: Unsupported AI engine for agent loop: #{engine}" unless mod_name

          mod = Object.const_get(mod_name)
          q_sys = <<~SYS
            #{system_role_content}

            INTENT: STATEMENT (this turn only)
              The user is making a statement — not an autonomous multi-step goal.
              Respond concisely in plain US English. Do NOT call tools unless a
              single factual lookup is strictly required and already present in
              context. Do NOT plan multi-step work. Do NOT invent task traces,
              planner monologue, rubocop, rake, or live recon.
          SYS

          txt =
            if mod.respond_to?(:chat)
              r = mod.chat(
                request: request,
                system_role_content: q_sys,
                spinner: true
              )
              if r.is_a?(Hash)
                (r.dig(:choices, -1, :content) || r.dig(:choices, -1, :text) || r[:content]).to_s
              else
                r.to_s
              end
            else
              messages = [
                { role: 'system', content: q_sys },
                { role: 'user', content: request }
              ]
              msg = call_engine(messages: messages, tools: nil)
              msg.is_a?(Hash) ? msg[:content].to_s : msg.to_s
            end

          txt = txt.to_s.strip
          txt = 'I do not have enough context to respond to your statement.' if txt.empty?

          append_session(session_id: session_id, role: 'user', content: request)
          append_session(session_id: session_id, role: 'assistant', content: txt)
          if defined?(Learning) && should_auto_introspect?(local: local_engine?, turn_fails: {}, iter: 0)
            Learning.auto_introspect(
              session_id: session_id,
              request: request,
              final: txt,
              predicted: 0.85,
              plan: [],
              ts_state: nil
            )
          end
          txt
        rescue StandardError => e
          warn "[pwn-ai/loop] answer_statement swallowed: #{e.class}: #{e.message}"
          'Noted.'
        end

        # Concise Q&A without multi-step task breakdown or plan_first thrash.
        private_class_method def self.answer_question(opts = {})
          request = opts[:request].to_s
          session_id = opts[:session_id]
          system_role_content = opts[:system_role_content].to_s
          engine = active_engine
          mod_name = ENGINE_MODS[engine]
          raise "ERROR: Unsupported AI engine for agent loop: #{engine}" unless mod_name

          mod = Object.const_get(mod_name)
          q_sys = <<~SYS
            #{system_role_content}

            INTENT: QUESTION (this turn only)
              The user asked a question — not an autonomous multi-step goal.
              Answer concisely in plain US English. Do NOT call tools unless a
              single factual lookup is strictly required and already present in
              context. Do NOT plan multi-step work. Do NOT invent task traces,
              planner monologue, rubocop, rake, or live recon.
          SYS

          txt =
            if mod.respond_to?(:chat)
              r = mod.chat(
                request: request,
                system_role_content: q_sys,
                spinner: true
              )
              if r.is_a?(Hash)
                (r.dig(:choices, -1, :content) || r.dig(:choices, -1, :text) || r[:content]).to_s
              else
                r.to_s
              end
            else
              messages = [
                { role: 'system', content: q_sys },
                { role: 'user', content: request }
              ]
              msg = call_engine(messages: messages, tools: nil)
              msg.is_a?(Hash) ? msg[:content].to_s : msg.to_s
            end

          txt = txt.to_s.strip
          txt = 'I do not have enough context to answer that yet.' if txt.empty?

          append_session(session_id: session_id, role: 'user', content: request)
          append_session(session_id: session_id, role: 'assistant', content: txt)
          if defined?(Learning) && should_auto_introspect?(local: local_engine?, turn_fails: {}, iter: 0)
            Learning.auto_introspect(
              session_id: session_id,
              request: request,
              final: txt,
              predicted: 0.85,
              plan: [],
              ts_state: nil
            )
          end
          txt
        rescue StandardError => e
          warn "[pwn-ai/loop] answer_question swallowed: #{e.class}: #{e.message}"
          "Could not answer the question (#{e.class}: #{e.message})."
        end

        private_class_method def self.answer_greeting(opts = {})
          request = opts[:request].to_s
          session_id = opts[:session_id]
          txt = <<~ACK.strip
            Acknowledged. System online - ready for a security task whenever you are.
          ACK

          append_session(session_id: session_id, role: 'user', content: request)
          append_session(session_id: session_id, role: 'assistant', content: txt)
          if defined?(Learning) && should_auto_introspect?(local: local_engine?, turn_fails: {}, iter: 0)
            Learning.auto_introspect(
              session_id: session_id,
              request: request,
              final: txt,
              predicted: 0.95,
              plan: ['Acknowledge greeting without tools or weather echo'],
              ts_state: nil
            )
          end
          txt
        rescue StandardError => e
          warn "[pwn-ai/loop] answer_greeting swallowed: #{e.class}: #{e.message}"
          'Acknowledged. Ready for a security task.'
        end

        private_class_method def self.answer_howto(opts = {})
          request = opts[:request].to_s
          session_id = opts[:session_id]
          system_role_content = opts[:system_role_content].to_s
          engine = active_engine
          mod_name = ENGINE_MODS[engine]
          raise "ERROR: Unsupported AI engine for agent loop: #{engine}" unless mod_name

          mod = Object.const_get(mod_name)
          howto_sys = <<~SYS
            #{system_role_content}

            INTENT: HOW-TO / DOCUMENTATION (this turn only)
              The user wants a concise explanation of how to use a tool or technique.
              Answer in plain US English with example command lines only.
              Do NOT call tools. Do NOT plan multi-step work. Do NOT run scans,
              probes, rubocop, rake, or host verification. Do NOT invent task
              traces or internal planner monologue. Do NOT claim you ran anything.
              If the topic is network discovery, give safe lab examples and note
              that live sweeps need explicit in-scope authorization.
          SYS

          txt =
            if mod.respond_to?(:chat)
              r = mod.chat(
                request: request,
                system_role_content: howto_sys,
                spinner: true
              )
              if r.is_a?(Hash)
                (r.dig(:choices, -1, :content) || r.dig(:choices, -1, :text) || r[:content]).to_s
              else
                r.to_s
              end
            else
              # chat_with_tools without tools
              messages = [
                { role: 'system', content: howto_sys },
                { role: 'user', content: request }
              ]
              msg = call_engine(messages: messages, tools: nil)
              msg.is_a?(Hash) ? msg[:content].to_s : msg.to_s
            end

          txt = txt.to_s.strip
          if txt.empty?
            txt = <<~FALLBACK
              Example hping3 ICMP ping sweep (lab / authorized targets only):

                # Needs root/CAP_NET_RAW for raw sockets
                sudo hping3 -1 --flood -c 1 192.168.1.x
                # Or loop a /24 carefully (slow rate to avoid DoS):
                for i in $(seq 1 254); do
                  sudo hping3 -1 -c 1 -N $i 192.168.1.$i 2>/dev/null | grep -q "icmp"                      && echo "up 192.168.1.$i"
                done

              Prefer intentional CIDR targeting over blind sweeps. Live host
              discovery without explicit engagement/scope authorization is out
              of bounds for this agent.
            FALLBACK
          end

          append_session(session_id: session_id, role: 'user', content: request)
          append_session(session_id: session_id, role: 'assistant', content: txt)
          if defined?(Learning) && should_auto_introspect?(local: local_engine?, turn_fails: {}, iter: 0)
            Learning.auto_introspect(
              session_id: session_id,
              request: request,
              final: txt,
              predicted: 0.9,
              plan: ['Explain tool usage without live recon'],
              ts_state: nil
            )
          end
          txt
        rescue StandardError => e
          warn "[pwn-ai/loop] answer_howto swallowed: #{e.class}: #{e.message}"
          "Could not produce a how-to answer (#{e.class}: #{e.message}). Retry with a frontier engine or ask for a specific flag/example."
        end

        # Classify pure-recall ask: :user (what did I say), :assistant (how did
        # you respond), or :either (vague memory cue — prefer user then asst).
        private_class_method def self.recall_target(opts = {})
          req = opts[:request].to_s
          return :assistant if req.match?(
            /
              how\s+did\s+you\s+respond|
              how\s+did\s+you\s+(?:just\s+)?(?:answer|reply)|
              what\s+(?:was|is)\s+your\s+(?:last|previous|prior)\s+(?:answer|response|reply)|
              what\s+did\s+you\s+(?:just\s+)?(?:say|answer|reply|respond)|
              remind\s+me\s+what\s+you\s+|
              repeat\s+your\s+(?:last|previous)
            /ix
          )
          return :user if req.match?(
            /
              what\s+did\s+i\s+|
              what\s+was\s+my\s+last|
              remind\s+me\s+what\s+i\s+|
              repeat\s+(?:my\s+)?(?:last|previous)|
              last\s+thing\s+i\s+said|
              say\s+that\s+again
            /ix
          )

          :either
        rescue StandardError
          :either
        end

        # Extract an explicit utterance the user wants matched in history
        # ("how did you respond when I said `howdy`?" / ... "X").
        private_class_method def self.extract_recall_match(opts = {})
          req = opts[:request].to_s
          # Backticks, straight/smart quotes
          m = req.match(/when\s+i\s+said\s*[,: ]\s*[`"'“”](.+?)[`"'“”]/im) ||
              req.match(/when\s+i\s+said\s*[,:]\s*(.+?)\s*\??\s*\z/im) ||
              req.match(/respond(?:ed)?\s+to\s*[`"'“”](.+?)[`"'“”]/im) ||
              req.match(/you\s+(?:said|answered|replied)\s+(?:to|when)\s*[`"'“”](.+?)[`"'“”]/im)
          return m[1].to_s.strip if m && !m[1].to_s.strip.empty?

          # "when I said that" / "to what I just said" → resolve non-meta pair
          return :non_meta if req.match?(/when\s+i\s+said\s+that\b|to\s+what\s+i\s+just\s+said\b|to\s+(?:my\s+)?(?:last|previous)\b/i)

          nil
        rescue StandardError
          nil
        end

        # Pure prior-turn / vague memory recall: answer from injected RECENT TURNS
        # (and/or one in-process Memory.recall) — never plan_first, never tool loop.
        private_class_method def self.answer_recall(opts = {})
          request = opts[:request].to_s
          session_id = opts[:session_id]
          system_role_content = opts[:system_role_content].to_s
          target = recall_target(request: request)

          prior_user = nil
          prior_asst = nil
          dialog = []
          pair = nil
          if defined?(PWN::Memory)
            match = extract_recall_match(request: request)
            # Assistant-target asks: resolve the full user↔assistant pair, not
            # merely the newest assistant line (which is often a prior recall
            # answer after nested follow-ups).
            if target == :assistant && PWN::Memory.respond_to?(:find_turn_pair)
              pair =
                if match == :non_meta || match.nil?
                  PWN::Memory.find_turn_pair(
                    session_id: session_id,
                    skip_meta: true,
                    pairs: 12,
                    max_chars: 4_000
                  )
                else
                  PWN::Memory.find_turn_pair(
                    session_id: session_id,
                    match: match,
                    skip_meta: true,
                    pairs: 12,
                    max_chars: 4_000
                  ) || PWN::Memory.find_turn_pair(
                    session_id: session_id,
                    skip_meta: true,
                    pairs: 12,
                    max_chars: 4_000
                  )
                end
            end

            if pair
              prior_user = { content: pair[:user_content] }
              prior_asst = { content: pair[:assistant_content] } if pair[:assistant_content]
            else
              # User-target / fallback: skip meta intermediate recall asks so
              # "what did I just say?" after a nested chain still surfaces the
              # original utterance when appropriate; default stays newest.
              skip_meta = target == :assistant
              prior_user = PWN::Memory.prior_user_message(
                session_id: session_id,
                max_chars: 4_000,
                skip_meta: skip_meta,
                pairs: 8
              )
              prior_asst = PWN::Memory.prior_assistant_message(
                session_id: session_id,
                max_chars: 4_000,
                skip_meta: skip_meta,
                pairs: 8
              )
            end
            dialog = PWN::Memory.recent_dialog(session_id: session_id, pairs: 4, max_chars: 1_500)
          end

          user_body = prior_user && prior_user[:content].to_s.strip
          asst_body = prior_asst && prior_asst[:content].to_s.strip
          user_body = nil if user_body.to_s.empty?
          asst_body = nil if asst_body.to_s.empty?

          # Deterministic short-circuit when session already holds the text.
          # One cheap recall — no LLM multi-tool thrash / plan_first.
          txt = nil
          plan_label = nil
          case target
          when :assistant
            if asst_body
              txt =
                if user_body
                  <<~ANS.strip
                    When you said:
                    #{user_body}

                    I responded:
                    #{asst_body}
                  ANS
                else
                  <<~ANS.strip
                    Immediately prior assistant response:

                    #{asst_body}
                  ANS
                end
              plan_label = 'Recall prior assistant turn from session transcript'
            elsif user_body
              # Fall back: at least return what the user said if asst missing.
              txt = <<~ANS.strip
                I do not have a prior assistant reply in this session yet.
                You just said:

                #{user_body}
              ANS
              plan_label = 'Recall prior user turn (assistant missing)'
            end
          when :user
            if user_body
              txt = <<~ANS.strip
                You just said:

                #{user_body}
              ANS
              plan_label = 'Recall prior user turn from session transcript'
            end
          else # :either — prefer user, then assistant
            if user_body
              txt = <<~ANS.strip
                You just said:

                #{user_body}
              ANS
              plan_label = 'Recall prior user turn from session transcript'
            elsif asst_body
              txt = <<~ANS.strip
                Immediately prior assistant response:

                #{asst_body}
              ANS
              plan_label = 'Recall prior assistant turn from session transcript'
            end
          end

          if txt
            append_session(session_id: session_id, role: 'user', content: request)
            append_session(session_id: session_id, role: 'assistant', content: txt)
            if defined?(Learning) && should_auto_introspect?(local: local_engine?, turn_fails: {}, iter: 0)
              Learning.auto_introspect(
                session_id: session_id,
                request: request,
                final: txt,
                predicted: 0.95,
                plan: [plan_label || 'Recall prior turn from session transcript'],
                ts_state: nil
              )
            end
            return txt
          end

          # Session empty / brand-new: one text-only chat with RECENT TURNS (if any)
          # still in system_role_content — still no tools / plan_first.
          engine = active_engine
          mod_name = ENGINE_MODS[engine]
          raise "ERROR: Unsupported AI engine for agent loop: #{engine}" unless mod_name

          mod = Object.const_get(mod_name)
          dialog_txt =
            if dialog && !dialog.empty?
              dialog.map { |t| "[#{t[:role]}] #{t[:content]}" }.join("\n")
            elsif prior_asst
              "[assistant] #{prior_asst[:content]}"
            else
              '(no prior user/assistant turns in this session yet)'
            end

          recall_sys = <<~SYS
            #{system_role_content}

            INTENT: PURE PRIOR-TURN / MEMORY RECALL (this turn only)
              Answer ONLY what the user just said or asked in this session.
              Use RECENT TURNS / the dialog snapshot below. Do NOT call tools.
              Do NOT plan. Do NOT run shell, sessions_view, or memory_recall.
              If nothing prior exists, say so in one short sentence.

            DIALOG SNAPSHOT:
            #{dialog_txt}
          SYS

          txt =
            if mod.respond_to?(:chat)
              r = mod.chat(
                request: request,
                system_role_content: recall_sys,
                spinner: true
              )
              if r.is_a?(Hash)
                (r.dig(:choices, -1, :content) || r.dig(:choices, -1, :text) || r[:content]).to_s
              else
                r.to_s
              end
            else
              messages = [
                { role: 'system', content: recall_sys },
                { role: 'user', content: request }
              ]
              msg = call_engine(messages: messages, tools: nil)
              msg.is_a?(Hash) ? msg[:content].to_s : msg.to_s
            end

          txt = txt.to_s.strip
          txt = 'I do not have a prior user turn in this session transcript yet.' if txt.empty?

          append_session(session_id: session_id, role: 'user', content: request)
          append_session(session_id: session_id, role: 'assistant', content: txt)
          if defined?(Learning) && should_auto_introspect?(local: local_engine?, turn_fails: {}, iter: 0)
            Learning.auto_introspect(
              session_id: session_id,
              request: request,
              final: txt,
              predicted: 0.85,
              plan: ['Recall prior turn (empty session fallback)'],
              ts_state: nil
            )
          end
          txt
        rescue StandardError => e
          warn "[pwn-ai/loop] answer_recall swallowed: #{e.class}: #{e.message}"
          "Could not recall the prior turn (#{e.class}: #{e.message})."
        end

        # Supported Method Parameters::
        # final = PWN::AI::Agent::Loop.run(
        #   request: 'required - what the human typed',
        #   session_id: 'optional - PWN::Sessions id (transcript is appended to it)',
        #   enabled_toolsets: 'optional - subset of Registry.toolsets, or nil for all',
        #   on_tool: 'optional - ->(name, args, result) callback for live UI',
        #   system_role_content: 'optional - override default system prompt (built from session_id if not provided)'
        # )

        public_class_method def self.run(opts = {})
          request = opts[:request].to_s
          session_id = opts[:session_id]
          on_tool = opts[:on_tool]
          TurnFinalizer.enter_user_path! if defined?(TurnFinalizer)
          engine = active_engine
          local  = local_engine?(engine: engine)

          # Cheap intent/kind FIRST - before PromptBuilder / Registry / TaskSummarizer
          # so greetings, FYIs, how-tos, recall, and simple Qs never pay the fat path.
          intent = request_intent(request: request)
          kind = request_kind(request: request)
          Thread.current[:pwn_request_intent] = intent
          Thread.current[:pwn_request_kind] = kind
          Thread.current[:pwn_recon_authorized] = recon_authorized?(request: request)
          Thread.current[:pwn_extinguished] = {}
          expose_current_session(session_id: session_id)
          Mistakes.check_user_correction(request: request, session_id: session_id) if defined?(Mistakes)

          cheap = opts[:force_tools] != true && (
            %i[greeting howto recall].include?(intent) ||
            (%i[statement question].include?(kind.to_sym) && intent != :recon_act)
          )

          # Greeting / light smalltalk: deterministic ack - no weather echo, no tools,
          # no PromptBuilder, no Registry.
          if intent == :greeting && opts[:force_tools] != true
            return answer_greeting(
              request: request,
              session_id: session_id
            )
          end

          # Thin system prompt only for remaining cheap paths (howto/recall/statement/question).
          if cheap
            system_role_content = opts[:system_role_content]
            if system_role_content.nil? || system_role_content.to_s.empty?
              system_role_content = PWN::AI::Agent::PromptBuilder.build(
                session_id: session_id,
                request: request,
                thin: true
              )
              opts[:system_role_content] = system_role_content
            end
            # How-to: never enter plan_first / task recon / tool thrash.
            if intent == :howto
              return answer_howto(
                request: request,
                session_id: session_id,
                system_role_content: system_role_content
              )
            end
            # Pure prior-turn / vague memory recall: one cheap path, no plan_first.
            if intent == :recall
              return answer_recall(
                request: request,
                session_id: session_id,
                system_role_content: system_role_content
              )
            end
            # General statements: acknowledge briefly - no multi-step task plan.
            if kind.to_sym == :statement
              return answer_statement(
                request: request,
                session_id: session_id,
                system_role_content: system_role_content
              )
            end
            # Pure questions (not host-evidence goals): concise answer, no multi-step plan.
            if kind.to_sym == :question
              return answer_question(
                request: request,
                session_id: session_id,
                system_role_content: system_role_content
              )
            end
          end

          # --- act / recon / autonomous_goal: full context + tools ---
          # Reuse precomputed kind so TaskSummarizer.fresh does not classify twice.
          ts_state = (TaskSummarizer.fresh(request: request, request_kind: kind) if defined?(TaskSummarizer) && TaskSummarizer.enabled? && Thread.current[:pwn_reflect_depth].to_i.zero?)
          system_role_content = opts[:system_role_content] ||= PWN::AI::Agent::PromptBuilder.build(
            session_id: session_id,
            request: request
          )

          Registry.discover
          maybe_refresh_extro_snapshot!
          opts[:enabled_toolsets] = default_interactive_toolsets(request: request) unless opts.key?(:enabled_toolsets)

          # R5 — open the live MDP episode BEFORE the first Registry.rank so
          # Q(s,a) can advise this turn. Planning still owns the task list.
          if defined?(PWN::AI::Agent::Policy) && Policy.respond_to?(:begin_episode)
            Policy.begin_episode(
              session_id: session_id,
              request: request,
              kind: kind,
              intent: intent,
              engine: engine,
              ts_state: ts_state
            )
          end

          # Initial tool pool from the user request (bootstrap only). After
          # TaskSummarizer.emit_plan! we re-rank using English tangible tasks
          # so generated tasks — not the bare request — drive which tools
          # the model may call.
          tools    = Registry.definitions(enabled: opts[:enabled_toolsets], relevance: request)
          messages = [{ role: 'system', content: system_role_content }]
          messages.concat(Learning.exemplars_for(request: request)) if local && defined?(Learning) && Learning.respond_to?(:exemplars_for)
          messages << { role: 'user', content: request }
          append_session(session_id: session_id, role: 'user', content: request)

          # Tangible-task breakdown ONLY for autonomous goals.
          # General statements and questions stay without multi-step plans.
          needs_breakdown =
            if defined?(TaskSummarizer) && TaskSummarizer.respond_to?(:needs_task_breakdown?)
              TaskSummarizer.needs_task_breakdown?(kind: kind, request: request)
            else
              kind.to_sym == :autonomous_goal
            end
          ts_state[:request_kind] = kind if ts_state.is_a?(Hash)
          if needs_breakdown
            task_summary_plan!(state: ts_state, request: request, on_tool: on_tool)
          elsif ts_state.is_a?(Hash) && defined?(TaskSummarizer)
            # Record kind on state; optional one-line kind banner (no task list).
            ts_state[:plan] = []
            ts_state[:request_kind] = kind
            if TaskSummarizer.respond_to?(:format_plan)
              banner = TaskSummarizer.format_plan(tasks: [], request: request, request_kind: kind)
              if banner && !banner.to_s.empty?
                ts_state[:plan_text] = banner
                ts_state[:plan_emitted] = true
                emit_task_summary(line: banner, on_tool: on_tool)
              end
            end
          end
          # Re-bind tools from English plan so task list is the sole driver of
          # tool exposure/ranking (Registry keyword router + CORE).
          if ts_state.is_a?(Hash) && defined?(TaskSummarizer) && TaskSummarizer.respond_to?(:relevance_query)
            rq = TaskSummarizer.relevance_query(state: ts_state, request: request)
            tools = Registry.definitions(enabled: opts[:enabled_toolsets], relevance: rq) unless rq.to_s.strip.empty?
          end
          # English-task-as-primary: inject tangible tasks only for autonomous goals.
          inject_task_focus!(messages: messages, state: ts_state, force: true, request: request) if needs_breakdown

          predicted = nil
          Thread.current[:pwn_plan_predicted] = nil
          cal_state = calibration_state
          force_plan = cal_state[:force_plan]
          # Skip plan_first for non-goals (statements/questions) and cheap intents.
          skip_plan = %i[howto recall greeting].include?(intent) ||
                      %i[statement question].include?(kind.to_sym) ||
                      !needs_breakdown
          if !skip_plan && (force_plan || agent_flag(key: :plan_first, default: local) || budget_exhaustion_hot?) && !Array(tools).empty?
            predicted = plan_first(messages: messages, request: request, ts_state: ts_state)
            # P22 — prefer explicit return; fall back to thread stash
            predicted = Thread.current[:pwn_plan_predicted] if predicted.nil?
            # unify_plan! may have rewritten English tasks — force refresh focus.
            # Re-rank tools from (possibly unified) English plan; never from
            # PLAN: tool-call scaffold jargon (unify_plan! refuses that).
            if ts_state.is_a?(Hash) && defined?(TaskSummarizer) && TaskSummarizer.respond_to?(:relevance_query)
              rq = TaskSummarizer.relevance_query(state: ts_state, request: request)
              tools = Registry.definitions(enabled: opts[:enabled_toolsets], relevance: rq) unless rq.to_s.strip.empty?
            end
            inject_task_focus!(messages: messages, state: ts_state, force: true, request: request)
          end
          if budget_exhaustion_hot?
            english_open = defined?(TaskSummarizer) && TaskSummarizer.respond_to?(:plan_open?) &&
                           TaskSummarizer.plan_open?(state: ts_state, messages: messages)
            hot_hint = if local_engine? && !english_open
                         '[pwn-ai/p17] Budget-exhaustion is the top open failure on this host. ' \
                           'Prefer the SHORTEST plan that finishes the ask (≤3 tool calls). ' \
                           'Emit a final answer as soon as you have evidence — do not explore.'
                       else
                         '[pwn-ai/p17] Budget-exhaustion is the top open failure on this host. ' \
                           'Prefer the shortest plan that FULLY finishes the ask — no polite ' \
                           'handoffs, no exploration side-quests. Emit a final answer as soon ' \
                           'as you have evidence; keep going with tools until the goal is done ' \
                           'or truly blocked.'
                       end
            messages << { role: 'user', content: hot_hint }
          end
          if force_plan && cal_state[:cal]
            messages << {
              role: 'user',
              content: "[pwn-ai/w3] engine=#{active_engine} is overconfident " \
                       "(brier=#{cal_state[:cal][:brier]}, overconf=#{cal_state[:cal][:overconfidence]}). " \
                       'Prefer high-judge exemplars, verify claims, and avoid speculative tool calls.'
            }
          end

          turn_fails = Hash.new(0)
          escalated  = false
          maybe_park_budget_scars!
          maybe_extinguish_parked!

          max_iters.times do |i|
            # 3.1 — compact history on local so tool dumps don't fill num_ctx
            compact_history!(messages: messages) if local
            # English-task-as-primary: when plan_idx advanced, tell the model
            # which plain-English task is active before the next tool batch.
            inject_task_focus!(messages: messages, state: ts_state, request: request)

            # P17 — on the final iteration, strip tools and demand a plain-text
            # answer. Without this the model happily emits one more tool_calls
            # batch, burns the last slot, and lands on budget_exhausted with
            # nothing the user (or ORM) can use.
            # P17 deepen — when budget_hot, force text-only on the LAST TWO
            # iters so a final tool_calls batch cannot burn the terminal slot.
            # P17 deepen³ — under hot, force text-only on last THREE of the
            # 8-iter cap so a late tool binge cannot burn every salvage slot.
            # P17 structural: default hot text-only tail stays 3 (do NOT deepen to 4/6).
            # Plan-faithful headroom — short plan executing cleanly → delay strip to
            # last 1–2 so multi-step goals are not predestined to exhaust under cap 8.
            hot = budget_exhaustion_hot?
            plan_steps = begin
              predicted_plan = predicted || Thread.current[:pwn_plan_predicted]
              if predicted_plan.is_a?(Hash)
                Array(predicted_plan[:steps] || predicted_plan[:tools] || predicted_plan[:plan]).size
              elsif predicted_plan.is_a?(Array)
                predicted_plan.size
              else
                predicted_plan.to_s.scan(/\b(?:shell|pwn_eval|memory_|mistakes_|skill_|extro_|learning_|sessions_)\w*/).size
              end
            rescue StandardError
              0
            end
            # Plan-faithful: delay the text-only strip when a plan is executing
            # cleanly. Remote hot allows longer plans (runway 25); local hot
            # still favors short plans under the 8-iter cap.
            plan_step_limit = local_engine? ? 3 : 12
            plan_faithful = hot && plan_steps.positive? && plan_steps <= plan_step_limit &&
                            turn_fails['empty_final'].to_i.zero? &&
                            turn_fails.values.sum < 2
            # Keep tools until the true last slot while English work remains.
            english_open = defined?(TaskSummarizer) && TaskSummarizer.respond_to?(:plan_open?) &&
                           TaskSummarizer.plan_open?(state: ts_state, messages: messages)
            text_only_iters = if !english_open && hot && !plan_faithful
                                local_engine? ? 3 : 2
                              else
                                1
                              end
            last_iter = (i >= max_iters - text_only_iters)
            if last_iter
              tag = i >= max_iters - 1 ? 'FINAL ITERATION' : 'PENULTIMATE — wrap up'
              messages << {
                role: 'user',
                content: "[pwn-ai/p17] #{tag} — do NOT call any more tools. " \
                         'Write the best complete answer you can from evidence already in this ' \
                         'transcript. If the goal is unfinished, report exactly what is done, ' \
                         'what is blocked, and the concrete remaining work — do NOT ask the ' \
                         'user to confirm the next step.'
              }
            end

            msg = call_engine(messages: messages, tools: last_iter ? nil : tools, ts_state: ts_state)
            if msg.nil?
              task_summary_flush!(state: ts_state, on_tool: on_tool)
              return '[pwn-ai] engine returned no message'
            end

            calls = Array(msg[:tool_calls])
            text  = msg[:content].to_s

            # Belt-and-suspenders: plain-text shell(...) / tool forms from local
            # models under weak TEMPLATE {{ .Prompt }} become real tool_calls.
            if calls.empty? && !text.strip.empty? && !last_iter &&
               defined?(Dispatch) && Dispatch.respond_to?(:tool_calls_from_text)
              coerced = Dispatch.tool_calls_from_text(text: text)
              if coerced.any?
                wired = coerced.map { |tc| openai_wire_tool_call(tool_call: tc) }
                msg = msg.merge(tool_calls: wired, content: nil, _text_tool_coerced: true)
                calls = wired
                text = ''
                warn "[pwn-ai/loop] coerced #{wired.length} text tool call(s) on iter=#{i}" if local
              end
            end

            # Empty-final guard (local/thinking models): Ollama sometimes
            # returns done_reason=stop with eval_count<=1, empty content, no
            # tool_calls — historically surface as a blank TUI reply. Do NOT
            # commit that as the answer; drop the empty assistant turn,
            # inject a one-shot nudge, and keep iterating.
            if calls.empty? && text.strip.empty?
              warn "[pwn-ai/loop] empty final from #{engine} on iter=#{i}; nudging" if local
              messages << {
                role: 'user',
                content: 'Your previous reply was empty (no tool_calls and no content). ' \
                         'Either call a tool now, or write the final answer for the user as plain text. ' \
                         'Do not reply with an empty message.'
              }
              turn_fails['empty_final'] += 1
              next
            end

            messages << msg

            if calls.empty?
              # P28 — refuse polite mid-goal handoffs so multi-step tasks stay autonomous.
              if incomplete_final?(text: text, last_iter: last_iter) && turn_fails['incomplete_final'].to_i < 4
                turn_fails['incomplete_final'] += 1
                warn "[pwn-ai/loop] incomplete final on iter=#{i}; continuing autonomously"
                messages << {
                  role: 'user',
                  content: '[pwn-ai/p28] That reply was incomplete (handoff or narrated next step). ' \
                           'Do NOT monologue about what you will try. Do NOT ask the user to ' \
                           'confirm. Emit NATIVE tool_calls NOW (e.g. shell with a concrete ' \
                           'command). Never print shell(...) as plain text. Only emit a final ' \
                           'answer when the request is complete or truly blocked with evidence.'
                }
                next
              end
              append_session(session_id: session_id, role: 'assistant', content: text)
              Learning.auto_introspect(session_id: session_id, request: request, final: text, predicted: predicted, plan: ts_state && ts_state[:plan], ts_state: ts_state) if defined?(Learning) && should_auto_introspect?(local: local, turn_fails: turn_fails, iter: i)
              maybe_finish_policy(session_id: session_id, proxy_ok: true, ts_state: ts_state)
              task_summary_flush!(state: ts_state, on_tool: on_tool)
              return text
            end

            # One executive task brief for the whole collection, then the
            # individual tool lines. pwn-ai → task is one-to-many with tools.
            task_summary_about_to!(
              state: ts_state,
              tools: calls.map do |tool_call|
                {
                  name: tool_call.dig(:function, :name).to_s,
                  args: tool_call.dig(:function, :arguments)
                }
              end,
              request: request,
              on_tool: on_tool
            )

            calls.each do |tc|
              name    = tc.dig(:function, :name).to_s
              args    = tc.dig(:function, :arguments)
              entry   = Registry.lookup(name: name)
              started = Time.now
              if Thread.current[:pwn_extinguished].is_a?(Hash) && Thread.current[:pwn_extinguished][name]
                raw = JSON.generate(
                  success: false,
                  error: "extinguished_repeat: #{name} already failed this signature this turn — change args or tool",
                  result: { stdout: '', stderr: "extinguished_repeat: #{name}", exit: 2 }
                )
              else
                raw = Dispatch.call(tool_call: tc)
              end
              tele    = record_metrics(name: name, started: started, raw: raw, args: args, session_id: session_id, engine: engine, ts_state: ts_state)
              result  = Result.condition(content: raw, entry: entry)

              unless tele[:ok]
                fkey = Digest::SHA256.hexdigest("#{name}|#{args}")[0, 16]
                turn_fails[fkey] += 1
                persist = tele.dig(:mistake, :count).to_i
                count   = [turn_fails[fkey], persist].max
                hint    = defined?(Mistakes) ? Mistakes.correction_hint(tool: name, error: tele[:err] || raw[0, 300]) : ''
                # S2 — counterfactual A/B: at the repeat threshold, fork an
                # alt-persona branch, judge both, inject the winner. Real
                # advantage estimation; (loser, winner) → DPO preference.
                thresh = defined?(Mistakes) ? Mistakes::REPEAT_THRESHOLD : 3
                # P17 — never fork counterfactual when budget fingerprints dominate:
                # CF is another mini agent loop and is the #1 amplifier of
                # iteration-budget exhaustion on this host.
                if count >= thresh && !escalated && defined?(Curriculum) && !budget_exhaustion_hot?
                  cf = (turn_fails["cf:#{fkey}"] += 1) == 1 ? Curriculum.counterfactual(request: request, name: name, args: args, error: tele[:err] || raw[0, 200], hint: hint) : nil
                  hint = "#{hint}\n[pwn-ai/counterfactual] branch #{cf[:branch]} (score=#{cf[:score].round(2)}): #{cf[:content]}" if cf
                end
                result = guard_repeated_failure(name: name, count: count, hint: hint, result: result, mistake: tele[:mistake], args: args, shape: tele.dig(:mistake, :shape))
              end

              on_tool&.call(name, args, result)
              task_summary_record!(state: ts_state, name: name, args: args, result: result, on_tool: on_tool)

              messages << {
                role: 'tool',
                tool_call_id: tc[:id] || tc['id'] || "call_#{i}",
                name: name,
                content: result
              }
              append_session(
                session_id: session_id,
                role: 'tool',
                content: "#{name} → #{result[0, 1_024]}"
              )
            end

            # P17 — evidence-enough early final (finish-under-N). When tools already
            # answered the ask, inject a synthesis nudge once and let the next
            # non-incomplete text final win — do not burn remaining iters to exhaust.
            if !last_iter && evidence_enough_to_finalize?(
              messages: messages,
              turn_fails: turn_fails,
              i: i,
              max_iters: max_iters,
              request: request,
              plan_steps: plan_steps,
              ts_state: ts_state
            ) && turn_fails['evidence_final'].to_i < 1
              turn_fails['evidence_final'] += 1
              messages << {
                role: 'user',
                content: '[pwn-ai/p17] Evidence from the last tool results is enough to answer. ' \
                         'Do NOT call more tools. Write the complete final answer now from that ' \
                         'evidence. If anything remains blocked, state exactly what and stop.'
              }
            end

            # P17 — hard stop: empty-final thrash or cumulative fails past cap.
            # Prefer a short apologetic final over another 10 useless tool dumps
            # that poison ORM/PRM/DPO with terminal failures.
            empty_n = turn_fails['empty_final'].to_i
            fail_n  = turn_fails.values.sum
            if empty_n >= BUDGET_EMPTY_FINAL_STOP || fail_n >= BUDGET_HARD_STOP_FAILS
              msg = if empty_n >= BUDGET_EMPTY_FINAL_STOP
                      '[pwn-ai] stopped: repeated empty finals (budget thrash guard)'
                    else
                      '[pwn-ai] stopped: too many in-turn failures (budget thrash guard)'
                    end
              if defined?(Mistakes)
                Mistakes.record(
                  tool: 'agent_loop',
                  error: "budget thrash guard fired empty=#{empty_n} fails=#{fail_n} iter=#{i}",
                  session_id: session_id,
                  source: :loop,
                  shape: :budget_thrash
                )
              end
              append_session(session_id: session_id, role: 'assistant', content: msg)
              Learning.auto_introspect(session_id: session_id, request: request, final: msg, predicted: predicted, plan: ts_state && ts_state[:plan], ts_state: ts_state) if defined?(Learning) && should_auto_introspect?(local: local, turn_fails: turn_fails, iter: i)
              maybe_finish_policy(session_id: session_id, proxy_ok: false, ts_state: ts_state)
              task_summary_flush!(state: ts_state, on_tool: on_tool)
              return msg
            end

            next unless local && !escalated && turn_fails.values.sum >= ESCALATE_AFTER_FAILS

            hint = escalate(request: request, turn_fails: turn_fails, session_id: session_id)
            if hint
              messages << { role: 'tool', tool_call_id: "escalation_#{i}", name: 'frontier_hint', content: hint }
              append_session(session_id: session_id, role: 'tool', content: "frontier_hint → #{hint[0, 1_024]}")
            end
            escalated = true
          end

          # P17 — exhaust path must still feed Learning so ORM/PRM/HER see the
          # failure (previously we only Mistakes.record'd and returned a bare
          # string — no session row, no judge, no hindsight).
          final_msg = '[pwn-ai] iteration budget exhausted'
          if defined?(Mistakes)
            Mistakes.record(
              tool: 'agent_loop',
              error: 'iteration budget exhausted without a final answer',
              session_id: session_id,
              source: :loop,
              shape: :budget_exhausted
            )
          end
          append_session(session_id: session_id, role: 'assistant', content: final_msg)
          Learning.auto_introspect(session_id: session_id, request: request, final: final_msg, predicted: predicted, plan: ts_state && ts_state[:plan], ts_state: ts_state) if defined?(Learning) && should_auto_introspect?(local: local, turn_fails: turn_fails, iter: max_iters)
          maybe_finish_policy(session_id: session_id, proxy_ok: false, ts_state: ts_state)
          task_summary_flush!(state: ts_state, on_tool: on_tool)
          final_msg
        ensure
          TurnFinalizer.leave_user_path! if defined?(TurnFinalizer)
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              final = PWN::AI::Agent::Loop.run(
                request: 'what does `id` return on this host?',
                session_id: PWN::Sessions.create[:id],
                enabled_toolsets: %w[terminal pwn memory skills],
                on_tool: ->(name, args, result) { puts "→ \#{name}: \#{result[0,1_024]}" },
                system_role_content: 'You are a helpful assistant that can call tools to answer questions.'
              )
              # Live task summaries (default ON): BEFORE each tool *collection*,
              # on_tool('task', high_level_brief, '') — one-to-many with real tools.
              # Task lines never carry a result payload (no result row in the TUI).
              # so repl.rb prints name=task with arg_preview=summary. Also coalesce bursts into
              # via on_tool only: [ ts → pwn-ai → task ] <brief> (no [pwn-ai/task] prefix)
              # Toggle via PWN::Env[:ai][:agent]:
              #   task_summary: true|false
              #   task_summary_every: 5          # emit every N tools
              #   task_summary_interval_s: 8.0   # or every N seconds
              #   task_summary_verbose: false

              Supported engines: #{ENGINE_MODS.keys.join(', ')}
              Set PWN::Env[:ai][:active] to choose; PWN::Env[:ai][:agent][:max_iters] to bound.

              Intent routing (all engines; critical for ollama/openwebui):
                how-to / usage questions → text-only explanation (no tools, no plan_first)
                pure prior-turn recall ("what did I just say?") → answer_recall (no tools)
                pure greeting / light smalltalk → answer_greeting (no tools, no weather echo)
                live subnet sweeps without scope language → refuse
                :recon_authorized    - Boolean session flag to allow raw-socket / sweep tools
              Local-model scaffolding (PWN::Env[:ai][:agent]):
                :plan_first          - Boolean, plan-then-act pre-pass (default: local engine :ollama/:openwebui)
                :tool_router         - Boolean/nil, slim Registry.definitions (nil=auto on for ollama)
                :escalation_persona  - Swarm persona name for frontier corrective hints when stuck
                :critic              - S3 constitutional critic before every final (Boolean)
                :red_team_plan       - S4 adversarial plan review after plan_first (Boolean)
                :counterfactual      - S2 A/B branch on REPEAT_THRESHOLD → DPO pair (Boolean)
                :hindsight           - C3 HER-relabel failures (Boolean, default true)
                :policy              - R5 live tabular Q / REINFORCE (Boolean, default true; advisory only)
                :verify_as_reward    - E3 ground every final via extro_verify (Boolean)

              P28 autonomy: incomplete-final detector refuses mid-goal handoffs;
              W3 overconf max_iters_cap is 120 on remote engines (8 on ollama).
              P17 budget-hot caps max_iters to 24 on ollama and 75 on remote engines
              so long multi-step goals keep a usable runway while thrash is cooled.

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
