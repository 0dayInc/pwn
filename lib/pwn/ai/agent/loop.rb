# frozen_string_literal: true

require 'json'

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
      module Loop
        DEFAULT_MAX_ITERS = 25

        ENGINE_MODS = {
          openai: 'PWN::AI::OpenAI',
          grok: 'PWN::AI::Grok',
          ollama: 'PWN::AI::Ollama',
          anthropic: 'PWN::AI::Anthropic',
          gemini: 'PWN::AI::Gemini'
        }.freeze

        # Supported Method Parameters::
        # final = PWN::AI::Agent::Loop.run(
        #   user_text: 'required - what the human typed',
        #   session_id: 'optional - PWN::Sessions id (transcript is appended to it)',
        #   enabled_toolsets: 'optional - subset of Registry.toolsets, or nil for all',
        #   on_tool: 'optional - ->(name, args, result) callback for live UI'
        # )

        public_class_method def self.run(opts = {})
          user_text  = opts[:user_text].to_s
          session_id = opts[:session_id]
          on_tool    = opts[:on_tool]

          Registry.discover

          tools    = Registry.definitions(enabled: opts[:enabled_toolsets])
          messages = [
            { role: 'system', content: PromptBuilder.build(session_id: session_id) },
            { role: 'user',   content: user_text }
          ]
          append_session(session_id: session_id, role: 'user', content: user_text)

          max_iters.times do |i|
            msg = call_engine(messages: messages, tools: tools)
            return '[pwn-ai] engine returned no message' if msg.nil?

            messages << msg
            calls = Array(msg[:tool_calls])

            if calls.empty?
              text = msg[:content].to_s
              append_session(session_id: session_id, role: 'assistant', content: text)
              return text
            end

            calls.each do |tc|
              name   = tc.dig(:function, :name).to_s
              entry  = Registry.lookup(name: name)
              raw    = Dispatch.call(tool_call: tc)
              result = Result.condition(content: raw, entry: entry)

              on_tool&.call(name, tc.dig(:function, :arguments), result)

              messages << {
                role: 'tool',
                tool_call_id: tc[:id] || tc['id'] || "call_#{i}",
                name: name,
                content: result
              }
              append_session(session_id: session_id, role: 'tool', content: "#{name} → #{result[0, 400]}")
            end
          end

          '[pwn-ai] iteration budget exhausted'
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

        public_class_method def self.call_engine(opts = {})
          messages = opts[:messages]
          tools    = opts[:tools]

          engine = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s.downcase.to_sym
          engine = :openai if engine == :''

          mod_name = ENGINE_MODS[engine]
          raise "ERROR: Unsupported AI engine for agent loop: #{engine}" unless mod_name

          mod = Object.const_get(mod_name)
          if mod.respond_to?(:chat_raw)
            normalise_openai(response: mod.chat_raw(messages: messages, tools: tools, spinner: true))
          else
            degrade_text_only(mod: mod, messages: messages)
          end
        end

        # Supported Method Parameters::
        # msg = PWN::AI::Agent::Loop.normalise_openai(
        #   response: 'required - raw chat_raw response Hash from any provider'
        # )

        public_class_method def self.normalise_openai(opts = {})
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
          # Preserve provider-native content blocks so chat_raw can round-trip
          # them exactly on the next iteration (e.g. Anthropic requires the
          # original tool_use block to precede a tool_result).
          out[:_native_content] = msg[:_native_content] if msg[:_native_content]
          out
        end

        private_class_method def self.degrade_text_only(opts = {})
          mod      = opts[:mod]
          messages = opts[:messages]

          warn "[pwn-ai] #{mod} has no chat_raw — falling back to text-only (no tool-calling)"
          sys  = messages.find { |m| m[:role] == 'system' }
          user = messages.rfind { |m| m[:role] == 'user' }
          r = mod.chat(request: user[:content], system_role_content: sys&.[](:content), spinner: true)
          txt = r.is_a?(Hash) ? (r.dig(:choices, -1, :content) || r.dig(:choices, -1, :text)).to_s : r.to_s
          { role: 'assistant', content: txt, tool_calls: [] }
        end

        private_class_method def self.max_iters
          v = (PWN::Env.dig(:ai, :agent, :max_iters) if defined?(PWN::Env))
          v.to_i.positive? ? v.to_i : DEFAULT_MAX_ITERS
        rescue StandardError
          DEFAULT_MAX_ITERS
        end

        private_class_method def self.append_session(opts = {})
          session_id = opts[:session_id]
          return unless session_id && defined?(PWN::Sessions)

          PWN::Sessions.append(session_id: session_id, role: opts[:role], content: opts[:content])
        rescue StandardError
          nil
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
                user_text: 'what does `id` return on this host?',
                session_id: PWN::Sessions.create[:id],
                enabled_toolsets: %w[terminal pwn memory skills],
                on_tool: ->(name, args, result) { puts "→ \#{name}: \#{result[0,80]}" }
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
