# frozen_string_literal: true

require 'json'
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

        ENGINE_MODS = {
          openai: 'PWN::AI::OpenAI',
          grok: 'PWN::AI::Grok',
          ollama: 'PWN::AI::Ollama',
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

        private_class_method def self.max_iters
          v = (PWN::Env.dig(:ai, :agent, :max_iters) if defined?(PWN::Env))
          n = v.to_i.positive? ? v.to_i : DEFAULT_MAX_ITERS
          # 0.3 — frontier leakage: live max_iters=80 burns local models.
          # Cap ollama at 25 unless the operator set an explicit lower value.
          n = 25 if active_engine == :ollama && n > 25
          # P7 — W3 controller: when this engine is badly overconfident,
          # shrink the tool budget so thrash can't compound on bad plans.
          cal = calibration_state
          n = [n, cal[:max_iters_cap]].min if cal[:overconfident]
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
          return { overconfident: false, force_plan: false, force_critic: false, max_iters_cap: 25, cal: cal } if n < 8

          brier = cal[:brier].to_f
          over  = cal[:overconfidence].to_f
          bad   = brier > 0.35 || over > 0.25
          {
            overconfident: bad,
            force_plan: bad,
            force_critic: bad,
            max_iters_cap: bad ? 12 : 25,
            cal: cal
          }
        rescue StandardError
          { overconfident: false, force_plan: false, force_critic: false, max_iters_cap: 25 }
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
          m = nil
          if !sem[:semantic_ok] && defined?(Mistakes)
            # E1 — automatic blame attribution: if this tool just tripped a
            # CUSUM changepoint AND extro drift is present, tag the mistake
            # cause: :env_drift so it does NOT count toward [REPEATING].
            cause = attribute_cause(name: name)
            m = Mistakes.record(tool: name, error: sem[:err] || raw[0, 300], args: opts[:args], session_id: opts[:session_id], source: :tool, cause: cause, shape: sem[:shape])
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

          guard = "[pwn-ai/mistakes] REPEATED FAILURE — this #{opts[:name]} failure signature has " \
                  "occurred #{count}× (across sessions). DO NOT retry it verbatim; change " \
                  'arguments, pick a different tool, apply the KNOWN FIX below if present, or ' \
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
          plan_msg = call_engine(
            messages: messages + [{ role: 'user',
                                    content: 'Before acting: (1) list the exact tool calls (name + key args) you will make, in order; (2) on the LAST line write "p(success)=<0.0-1.0>". Reply ONLY with the numbered plan + that line — do NOT call any tool yet.' }],
            tools: nil
          )
          return nil unless plan_msg && !plan_msg[:content].to_s.strip.empty?

          plan = plan_msg[:content].to_s.strip
          messages << { role: 'assistant', content: "PLAN:\n#{plan}" }
          # S4 — adversarial plan review grounded in THIS host's telemetry
          if defined?(Curriculum)
            rt = Curriculum.red_team_plan(request: opts[:request], plan: plan)
            messages << { role: 'user', content: rt } if rt
          end
          # W3 — extract predicted p(success) for calibration tracking
          plan[/p\(success\)\s*=\s*([01](?:\.\d+)?)/i, 1]&.to_f
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
                  arguments: tc.dig(:function, :arguments) || tc[:arguments]
                }
              }
            end
          }
          # Preserve provider-native content blocks so chat can round-trip
          # them exactly on the next iteration (e.g. Anthropic requires the
          # original tool_use block to precede a tool_result).
          out[:_native_content] = msg[:_native_content] if msg[:_native_content]
          out[:thinking] = msg[:thinking] if msg[:thinking]
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
            response = mod.chat_with_tools(
              messages: messages,
              tools: tools,
              spinner: true
            )
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
          engine = active_engine
          local  = engine == :ollama
          system_role_content = opts[:system_role_content] ||= PWN::AI::Agent::PromptBuilder.build(session_id: session_id, request: request)

          Registry.discover
          expose_current_session(session_id: session_id)
          Mistakes.check_user_correction(request: request, session_id: session_id) if defined?(Mistakes)

          tools    = Registry.definitions(enabled: opts[:enabled_toolsets], relevance: request)
          messages = [{ role: 'system', content: system_role_content }]
          messages.concat(Learning.exemplars_for(request: request)) if local && defined?(Learning) && Learning.respond_to?(:exemplars_for)
          messages << { role: 'user', content: request }
          append_session(session_id: session_id, role: 'user', content: request)

          predicted = nil
          cal_state = calibration_state
          force_plan = cal_state[:force_plan]
          predicted = plan_first(messages: messages, request: request) if (force_plan || agent_flag(key: :plan_first, default: local)) && !Array(tools).empty?
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

          max_iters.times do |i|
            # 3.1 — compact history on local so tool dumps don't fill num_ctx
            compact_history!(messages: messages) if local

            msg = call_engine(messages: messages, tools: tools)
            return '[pwn-ai] engine returned no message' if msg.nil?

            calls = Array(msg[:tool_calls])
            text  = msg[:content].to_s

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
              append_session(session_id: session_id, role: 'assistant', content: text)
              Learning.auto_introspect(session_id: session_id, request: request, final: text, predicted: predicted) if defined?(Learning) && should_auto_introspect?(local: local, turn_fails: turn_fails, iter: i)
              return text
            end

            calls.each do |tc|
              name    = tc.dig(:function, :name).to_s
              args    = tc.dig(:function, :arguments)
              entry   = Registry.lookup(name: name)
              started = Time.now
              raw     = Dispatch.call(tool_call: tc)
              tele    = record_metrics(name: name, started: started, raw: raw, args: args, session_id: session_id, engine: engine)
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
                if count >= thresh && !escalated && defined?(Curriculum)
                  cf = (turn_fails["cf:#{fkey}"] += 1) == 1 ? Curriculum.counterfactual(request: request, name: name, args: args, error: tele[:err] || raw[0, 200], hint: hint) : nil
                  hint = "#{hint}\n[pwn-ai/counterfactual] branch #{cf[:branch]} (score=#{cf[:score].round(2)}): #{cf[:content]}" if cf
                end
                result = guard_repeated_failure(name: name, count: count, hint: hint, result: result)
              end

              on_tool&.call(name, args, result)

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

            next unless local && !escalated && turn_fails.values.sum >= ESCALATE_AFTER_FAILS

            hint = escalate(request: request, turn_fails: turn_fails, session_id: session_id)
            if hint
              messages << { role: 'tool', tool_call_id: "escalation_#{i}", name: 'frontier_hint', content: hint }
              append_session(session_id: session_id, role: 'tool', content: "frontier_hint → #{hint[0, 1_024]}")
            end
            escalated = true
          end

          Mistakes.record(tool: 'agent_loop', error: 'iteration budget exhausted without a final answer', session_id: session_id, source: :loop) if defined?(Mistakes)
          '[pwn-ai] iteration budget exhausted'
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

              Supported engines: #{ENGINE_MODS.keys.join(', ')}
              Set PWN::Env[:ai][:active] to choose; PWN::Env[:ai][:agent][:max_iters] to bound.

              Local-model scaffolding (PWN::Env[:ai][:agent]):
                :plan_first          - Boolean, plan-then-act pre-pass (default: engine == :ollama)
                :tool_router         - Boolean/nil, slim Registry.definitions (nil=auto on for ollama)
                :escalation_persona  - Swarm persona name for frontier corrective hints when stuck
                :critic              - S3 constitutional critic before every final (Boolean)
                :red_team_plan       - S4 adversarial plan review after plan_first (Boolean)
                :counterfactual      - S2 A/B branch on REPEAT_THRESHOLD → DPO pair (Boolean)
                :hindsight           - C3 HER-relabel failures (Boolean, default true)
                :verify_as_reward    - E3 ground every final via extro_verify (Boolean)

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
