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
      module Loop
        DEFAULT_MAX_ITERS = 777

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
          v.to_i.positive? ? v.to_i : DEFAULT_MAX_ITERS
        rescue StandardError
          DEFAULT_MAX_ITERS
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
          ok      = raw.include?('"success":true') && !raw.match?(/"exit":[1-9]/)
          err     = raw[/"error":"([^"]{1,300})"/, 1]
          err   ||= raw[/"stderr":"([^"]{4,300})"/, 1] unless ok
          dur     = started ? (Time.now - started) : 0.0
          Metrics.record(name: name, success: ok, duration: dur, error: err) if defined?(Metrics)
          m = nil
          m = Mistakes.record(tool: name, error: err || raw[0, 300], args: opts[:args], session_id: opts[:session_id], source: :tool) if !ok && defined?(Mistakes)
          { ok: ok, err: err, mistake: m }
        rescue StandardError
          { ok: true, err: nil, mistake: nil }
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

        # Supported Method Parameters::
        # msg = PWN::AI::Agent::Loop.normalize_llm(
        #   response: 'required - chat_with_tools response Hash from any provider'
        # )

        private_class_method def self.normalize_llm(opts = {})
          resp = opts[:response]
          return nil unless resp.is_a?(Hash)

          msg = resp.dig(:choices, 0, :message) || resp[:assistant_message]
          return nil unless msg

          out = {
            role: 'assistant',
            content: msg[:content],
            tool_calls: Array(msg[:tool_calls]).map do |tc|
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

          engine = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s.downcase.to_sym
          engine = :openai if engine == :''

          mod_name = ENGINE_MODS[engine]
          raise "ERROR: Unsupported AI engine for agent loop: #{engine}" unless mod_name

          mod = Object.const_get(mod_name)
          if mod.respond_to?(:chat_with_tools)
            response = mod.chat_with_tools(
              messages: messages,
              tools: tools,
              spinner: true
            )
            normalize_llm(response: response)
          else
            degrade_text_only(mod: mod, messages: messages)
          end
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
          system_role_content = opts[:system_role_content] ||= PWN::AI::Agent::PromptBuilder.build(session_id: session_id)

          Registry.discover
          expose_current_session(session_id: session_id)
          Mistakes.check_user_correction(request: request, session_id: session_id) if defined?(Mistakes)

          tools    = Registry.definitions(enabled: opts[:enabled_toolsets])
          messages = [
            { role: 'system', content: system_role_content },
            { role: 'user',   content: request }
          ]
          append_session(session_id: session_id, role: 'user', content: request)

          turn_fails = Hash.new(0)

          max_iters.times do |i|
            msg = call_engine(messages: messages, tools: tools)
            return '[pwn-ai] engine returned no message' if msg.nil?

            messages << msg
            calls = Array(msg[:tool_calls])

            if calls.empty?
              text = msg[:content].to_s
              append_session(session_id: session_id, role: 'assistant', content: text)
              Learning.auto_reflect(session_id: session_id, request: request, final: text) if defined?(Learning)
              return text
            end

            calls.each do |tc|
              name    = tc.dig(:function, :name).to_s
              args    = tc.dig(:function, :arguments)
              entry   = Registry.lookup(name: name)
              started = Time.now
              raw     = Dispatch.call(tool_call: tc)
              tele    = record_metrics(name: name, started: started, raw: raw, args: args, session_id: session_id)
              result  = Result.condition(content: raw, entry: entry)

              unless tele[:ok]
                fkey = Digest::SHA256.hexdigest("#{name}|#{args}")[0, 16]
                turn_fails[fkey] += 1
                persist = tele.dig(:mistake, :count).to_i
                hint    = defined?(Mistakes) ? Mistakes.correction_hint(tool: name, error: tele[:err] || raw[0, 300]) : ''
                result  = guard_repeated_failure(
                  name: name,
                  count: [turn_fails[fkey], persist].max,
                  hint: hint,
                  result: result
                )
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

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
