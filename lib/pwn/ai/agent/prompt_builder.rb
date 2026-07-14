# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # Assembles the system prompt for every Loop.run invocation from
      # durable on-disk state: PWN::Env persona, host environment probe,
      # PWN::Memory facts, and PWN::Skills index.
      #
      # Re-injection IS the persistence mechanism: this is rebuilt fresh on
      # every user turn, so a memory_remember / skill_create from the prior
      # turn shows up here with no extra wiring.
      #
      # ENGINE-AWARE BUDGETING
      # ----------------------
      # Local models (Ollama) drown when handed the same 6-8 KB of MEMORY /
      # METRICS / MISTAKES / EXTROSPECTION context that a frontier model
      # shrugs off. .budget shrinks each block for :ollama (or whatever
      # PWN::Env[:ai][<engine>][:prompt_budget] says) so the small model
      # spends its attention on the request, not the harness.
      #
      # RELEVANCE-RANKED MEMORY
      # -----------------------
      # When Loop.run passes request: through, the MEMORY block is populated
      # by PWN::MemoryIndex.recall_semantic (embedding cosine over
      # ~/.pwn/memory.idx) instead of a recency dump — the 6 memories a
      # small model can afford are the 6 that actually matter for THIS turn.
      module PromptBuilder
        # Supported Method Parameters::
        # system_prompt = PWN::AI::Agent::PromptBuilder.build(
        #   session_id: 'optional - PWN::Sessions id to embed in the ENV block',
        #   request: 'optional - user request; enables relevance-ranked MEMORY when provided'
        # )

        public_class_method def self.build(opts = {})
          session_id = opts[:session_id]
          request = opts[:request]
          engine = active_engine
          b = budget
          base = (PWN::Env.dig(:ai, engine, :system_role_content) if defined?(PWN::Env)) || 'You are a world-class introspective offensive cyber security and research engineer.  You specialize in discovering zero day vulnerabilities focused on responsible disclosure prior to threat actors discovering and exploiting.  You are self-aware of your harness, pwn which begins with the ruby namespace `PWN` operating inside the pwn REPL.  For every request you first begin by determining if PWN has a module capable of satisfying the request.'

          "
            #{base}

            ENVIRONMENT
              host       : #{host_line}
              cwd        : #{Dir.pwd}
              ruby       : #{RUBY_VERSION}
              pwn        : #{pwn_version}
              session_id : #{session_id || '(none)'}

            #{memory_block(limit: b[:memory], request: request)}#{skills_block}#{learning_block(limit: b[:learning])}#{mistakes_block(limit: b[:mistakes])}#{metrics_block(limit: b[:metrics], engine: engine)}#{extrospection_block if b[:extro]}TOOL USE
              Use the provided function tools to act on the host. A reply with
              no tool_calls is treated as your FINAL answer to the user.
              Prefer `pwn_eval` for anything in the PWN:: namespace and `shell`
              for OS commands. Save durable facts with `memory_remember`.
          "
        end

        # Supported Method Parameters::
        # b = PWN::AI::Agent::PromptBuilder.budget
        #
        # Per-engine caps for each injected block. Override any key via
        # PWN::Env[:ai][<engine>][:prompt_budget][:memory|:metrics|:mistakes|
        # :learning|:extro]. :extro is a Boolean gate — Extrospection is the
        # heaviest block and rarely useful to a local model.

        public_class_method def self.budget
          eng = active_engine
          b   = (PWN::Env.dig(:ai, eng, :prompt_budget) if defined?(PWN::Env)) || {}
          local = eng == :ollama
          {
            memory: (b[:memory] || (local ? 6 : 25)).to_i,
            metrics: (b[:metrics] || (local ? 3 : 8)).to_i,
            mistakes: (b[:mistakes] || (local ?  3 :  6)).to_i,
            learning: (b[:learning] || (local ?  2 :  5)).to_i,
            extro: b[:extro].nil? ? !local : b[:extro]
          }
        rescue StandardError
          { memory: 25, metrics: 8, mistakes: 6, learning: 5, extro: true }
        end

        private_class_method def self.active_engine
          return :openai unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          PWN::Env.dig(:ai, :active).to_s.downcase.to_sym
        rescue StandardError
          :openai
        end

        private_class_method def self.host_line
          `uname -srm 2>/dev/null`.strip
        rescue StandardError
          RUBY_PLATFORM
        end

        private_class_method def self.pwn_version
          defined?(PWN::VERSION) ? PWN::VERSION : '?'
        end

        private_class_method def self.memory_block(opts = {})
          return '' unless defined?(PWN::Memory) && PWN::Memory.respond_to?(:to_context)

          limit = opts[:limit] || 25
          req   = opts[:request]
          ctx   = if req && defined?(PWN::MemoryIndex) && PWN::MemoryIndex.available?
                    PWN::MemoryIndex.to_context(query: req, limit: limit)
                  else
                    PWN::Memory.to_context(limit: limit)
                  end
          ctx.to_s.strip.empty? ? '' : "MEMORY#{ctx}\n\n"
        rescue StandardError
          ''
        end

        private_class_method def self.skills_block
          return '' unless defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) && !PWN::Skills.empty?

          lines = PWN::Skills.map do |name, meta|
            desc = meta[:description].to_s.strip
            if desc.empty?
              # legacy / stubbed entry without a parsed description — fall back
              desc = meta[:content].to_s.lines.reject { |l| l.strip.empty? || l.start_with?('---') }.first.to_s.strip
            end
            desc = desc[0, 100]
            rc = Array(meta[:references]).length
            ref_tag = rc.positive? ? " [#{rc} refs]" : ''
            "  - #{name}: #{desc}#{ref_tag}"
          end
          "SKILLS (call skill_view to read full body)\n#{lines.join("\n")}\n\n"
        rescue StandardError
          ''
        end

        private_class_method def self.learning_block(opts = {})
          return '' unless defined?(PWN::AI::Agent::Learning)

          ctx = PWN::AI::Agent::Learning.to_context(limit: opts[:limit] || 5).to_s
          ctx.strip.empty? ? '' : "LEARNING\n#{ctx}"
        rescue StandardError
          ''
        end

        private_class_method def self.mistakes_block(opts = {})
          return '' unless defined?(PWN::AI::Agent::Mistakes)

          ctx = PWN::AI::Agent::Mistakes.to_context(limit: opts[:limit] || 6).to_s
          ctx.strip.empty? ? '' : ctx
        rescue StandardError
          ''
        end

        private_class_method def self.metrics_block(opts = {})
          return '' unless defined?(PWN::AI::Agent::Metrics)

          ctx = PWN::AI::Agent::Metrics.to_context(limit: opts[:limit] || 8, engine: opts[:engine]).to_s
          ctx.strip.empty? ? '' : ctx
        rescue StandardError
          ''
        end

        private_class_method def self.extrospection_block
          return '' unless defined?(PWN::AI::Agent::Extrospection)

          ctx = PWN::AI::Agent::Extrospection.to_context.to_s
          ctx.strip.empty? ? '' : ctx
        rescue StandardError
          ''
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              system_prompt = PWN::AI::Agent::PromptBuilder.build(session_id: 'abc', request: 'nmap sweep 10/8')
              PWN::AI::Agent::PromptBuilder.budget   # => {memory:, metrics:, mistakes:, learning:, extro:}

              Override per-engine via:
                PWN::Env[:ai][:ollama][:prompt_budget] = { memory: 4, extro: false }

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
