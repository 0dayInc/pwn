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
      module PromptBuilder
        # Supported Method Parameters::
        # system_prompt = PWN::AI::Agent::PromptBuilder.build(
        #   session_id: 'optional - PWN::Sessions id to embed in the ENV block'
        # )

        public_class_method def self.build(opts = {})
          session_id = opts[:session_id]
          engine = active_engine
          base = (PWN::Env.dig(:ai, engine, :system_role_content) if defined?(PWN::Env)) || 'You are a world-class introspective offensive cyber security and research engineer.  You specialize in discovering zero day vulnerabilities focused on responsible disclosure prior to threat actors discovering and exploiting.  You are self-aware of your harness, pwn which begins with the ruby namespace `PWN` operating inside the pwn REPL.  For every request you first begin by determining if PWN has a module capable of satisfying the request.'

          "
            #{base}

            ENVIRONMENT
              host       : #{host_line}
              cwd        : #{Dir.pwd}
              ruby       : #{RUBY_VERSION}
              pwn        : #{pwn_version}
              session_id : #{session_id || '(none)'}

            #{memory_block}#{skills_block}#{learning_block}#{metrics_block}TOOL USE
              Use the provided function tools to act on the host. A reply with
              no tool_calls is treated as your FINAL answer to the user.
              Prefer `pwn_eval` for anything in the PWN:: namespace and `shell`
              for OS commands. Save durable facts with `memory_remember`.
          "
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

        private_class_method def self.memory_block
          return '' unless defined?(PWN::Memory) && PWN::Memory.respond_to?(:to_context)

          ctx = PWN::Memory.to_context(limit: 25).to_s
          ctx.strip.empty? ? '' : "MEMORY#{ctx}\n\n"
        rescue StandardError
          ''
        end

        private_class_method def self.skills_block
          return '' unless defined?(PWN::Skills) && PWN::Skills.is_a?(Hash) && !PWN::Skills.empty?

          lines = PWN::Skills.map do |name, meta|
            first = meta[:content].to_s.lines.reject { |l| l.strip.empty? || l.start_with?('---') }.first.to_s.strip
            first = first[0, 100]
            rc = Array(meta[:references]).length
            ref_tag = rc.positive? ? " [#{rc} refs]" : ''
            "  - #{name}: #{first}#{ref_tag}"
          end
          "SKILLS (call skill_view to read full body)\n#{lines.join("\n")}\n\n"
        rescue StandardError
          ''
        end

        private_class_method def self.learning_block
          return '' unless defined?(PWN::AI::Agent::Learning)

          ctx = PWN::AI::Agent::Learning.to_context(limit: 5).to_s
          ctx.strip.empty? ? '' : "LEARNING\n#{ctx}"
        rescue StandardError
          ''
        end

        private_class_method def self.metrics_block
          return '' unless defined?(PWN::AI::Agent::Metrics)

          ctx = PWN::AI::Agent::Metrics.to_context(limit: 8).to_s
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
              system_prompt = PWN::AI::Agent::PromptBuilder.build(session_id: 'abc')

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
