# frozen_string_literal: true

require 'digest'

module PWN
  module AI
    module Agent
      # Hermes-style prompt-cache breakpoints. The static system prefix +
      # SKILLS index stay cacheable; dynamic MEMORY / LEARNING / MISTAKES /
      # METRICS / EXTROSPECTION stay uncached so a turn-local write is not
      # baked into the prefix.
      #
      # Anthropic: system is an array of text blocks; the last static block
      # carries cache_control: { type: 'ephemeral' }.
      # OpenAI Chat Completions: two system/developer messages (static then
      # dynamic) plus prompt_cache_key for cache routing.
      # xAI Grok Chat Completions: the same message split plus the
      # x-grok-conv-id request header (sticky server routing).
      # Gemini generateContent: systemInstruction.parts = [static, dynamic]
      # so implicit prefix cache can hit the stable head.
      # Ollama: no-op.
      module PromptCache
        STATIC_HEAD = %w[ENVIRONMENT].freeze
        DYNAMIC_HEADS = [
          'MEMORY',
          'RECENT TURNS',
          'LEARNING',
          'OPERATOR INBOX',
          'KNOWN MISTAKES',
          'KNOWN FIXES',
          'TOOL EFFECTIVENESS',
          'POLICY',
          'EXTROSPECTION',
          'TOOL USE'
        ].freeze

        # Supported Method Parameters::
        # ok = PWN::AI::Agent::PromptCache.enabled?(engine: :anthropic)

        public_class_method def self.enabled?(opts = {})
          flag = agent_flag(key: :prompt_cache, default: true)
          return false if flag == false || flag.to_s.match?(/\A(0|false|no|off)\z/i)

          engine = (opts[:engine] || active_engine).to_s.downcase.to_sym
          supports.include?(engine)
        rescue StandardError
          false
        end

        # Supported Method Parameters::
        # parts = PWN::AI::Agent::PromptCache.split_system(text: system_prompt)
        #
        # → { static: String, dynamic: String, skills: String }

        public_class_method def self.split_system(opts = {})
          text = opts[:text].to_s
          return { static: '', dynamic: '', skills: '' } if text.empty?

          dyn_idx = first_dynamic_index(text: text)
          if dyn_idx.nil?
            skills = extract_skills(text: text)
            return { static: text, dynamic: '', skills: skills }
          end

          static = text[0...dyn_idx].rstrip
          dynamic = text[dyn_idx..].to_s
          { static: static, dynamic: dynamic, skills: extract_skills(text: static) }
        rescue StandardError
          { static: opts[:text].to_s, dynamic: '', skills: '' }
        end

        # Supported Method Parameters::
        # blocks = PWN::AI::Agent::PromptCache.anthropic_system_blocks(text: system_prompt)
        #
        # → [ {type:'text', text: static, cache_control:{type:'ephemeral'}},
        #     {type:'text', text: dynamic} ]  (empty blocks omitted)

        public_class_method def self.anthropic_system_blocks(opts = {})
          parts = split_system(text: opts[:text])
          blocks = []
          unless parts[:static].to_s.strip.empty?
            blocks << {
              type: 'text',
              text: parts[:static],
              cache_control: { type: 'ephemeral' }
            }
          end
          blocks << { type: 'text', text: parts[:dynamic] } unless parts[:dynamic].to_s.strip.empty?
          blocks
        rescue StandardError
          txt = opts[:text].to_s
          return [] if txt.strip.empty?

          [{ type: 'text', text: txt }]
        end

        # Supported Method Parameters::
        # messages = PWN::AI::Agent::PromptCache.openai_messages(messages: [...])
        #
        # Split the first system/developer message into a stable static
        # prefix and a turn-local dynamic tail so OpenAI / xAI implicit
        # prefix matching can hit across turns. Does NOT emit Anthropic
        # cache_control.

        public_class_method def self.openai_messages(opts = {})
          messages = Array(opts[:messages]).map { |m| m.is_a?(Hash) ? m.dup : m }
          idx = messages.index do |m|
            next false unless m.is_a?(Hash)

            %w[system developer].include?((m[:role] || m['role']).to_s)
          end
          return messages unless idx

          msg = messages[idx]
          role = msg[:role] || msg['role']
          text = (msg[:content] || msg['content']).to_s
          parts = split_system(text: text)
          return messages if parts[:static].to_s.strip.empty? || parts[:dynamic].to_s.strip.empty?

          static_msg = msg.dup
          if static_msg.key?(:content) || !static_msg.key?('content')
            static_msg[:content] = parts[:static]
          else
            static_msg['content'] = parts[:static]
          end

          dynamic_msg = if msg.key?(:role) || !msg.key?('role')
                          { role: role, content: parts[:dynamic] }
                        else
                          { 'role' => role, 'content' => parts[:dynamic] }
                        end

          messages[idx, 1] = [static_msg, dynamic_msg]
          messages
        rescue StandardError
          Array(opts[:messages])
        end

        # Supported Method Parameters::
        # inst = PWN::AI::Agent::PromptCache.gemini_system_instruction(text: system_prompt)
        #
        # → { parts: [{text: static}, {text: dynamic}] }  (empty omitted)

        public_class_method def self.gemini_system_instruction(opts = {})
          parts = split_system(text: opts[:text])
          out = []
          out << { text: parts[:static] } unless parts[:static].to_s.strip.empty?
          out << { text: parts[:dynamic] } unless parts[:dynamic].to_s.strip.empty?
          return nil if out.empty?

          { parts: out }
        rescue StandardError
          txt = opts[:text].to_s
          return nil if txt.strip.empty?

          { parts: [{ text: txt }] }
        end

        # Supported Method Parameters::
        # key = PWN::AI::Agent::PromptCache.cache_key(text: system_prompt)
        # key = PWN::AI::Agent::PromptCache.cache_key(key: 'explicit-override')
        #
        # Stable OpenAI prompt_cache_key / xAI x-grok-conv-id. Hashes the
        # static prefix so MEMORY / LEARNING churn does not rotate the key.

        public_class_method def self.cache_key(opts = {})
          explicit = opts[:key]
          return explicit.to_s unless explicit.to_s.strip.empty?

          raw = opts[:text].to_s
          static = raw.empty? ? '' : split_system(text: raw)[:static].to_s
          static = raw if static.strip.empty?
          static = 'pwn-ai' if static.strip.empty?
          "pwn-#{Digest::SHA256.hexdigest(static)[0, 24]}"
        rescue StandardError
          'pwn-ai'
        end

        # Supported Method Parameters::
        # n = PWN::AI::Agent::PromptCache.cache_marks(blocks: [...])

        public_class_method def self.cache_marks(opts = {})
          Array(opts[:blocks]).count do |b|
            next false unless b.is_a?(Hash)

            cc = b[:cache_control] || b['cache_control']
            cc.is_a?(Hash) && (cc[:type] || cc['type']).to_s == 'ephemeral'
          end
        end

        public_class_method def self.supports
          %i[anthropic openai grok gemini]
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              parts  = PWN::AI::Agent::PromptCache.split_system(text: system_prompt)
              blocks = PWN::AI::Agent::PromptCache.anthropic_system_blocks(text: system_prompt)
              msgs   = PWN::AI::Agent::PromptCache.openai_messages(messages: [...])
              inst   = PWN::AI::Agent::PromptCache.gemini_system_instruction(text: system_prompt)
              key    = PWN::AI::Agent::PromptCache.cache_key(text: system_prompt)
              # Engine chat_with_tools uses the helpers automatically when
              # PWN::Env[:ai][:agent][:prompt_cache] is truthy (default).

              Toggle via PWN::Env[:ai][:agent][:prompt_cache]
              #{self}.authors
          USAGE
        end

        private_class_method def self.first_dynamic_index(opts = {})
          text = opts[:text].to_s
          idxs = DYNAMIC_HEADS.filter_map do |head|
            i = text.index(/^#{Regexp.escape(head)}\b/)
            i
          end
          idxs.min
        end

        private_class_method def self.extract_skills(opts = {})
          text = opts[:text].to_s
          m = text.match(%r{^SKILLS[^\n]*\n(?:.*\n)*?(?=\n[A-Z][A-Z /]|\z)})
          m ? m[0] : ''
        rescue StandardError
          ''
        end

        private_class_method def self.active_engine
          return :openai unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          PWN::Env.dig(:ai, :active).to_s.downcase.to_sym
        rescue StandardError
          :openai
        end

        private_class_method def self.agent_flag(opts = {})
          key = opts[:key]
          default = opts[:default]
          return default unless defined?(PWN::Env)

          val = PWN::Env.dig(:ai, :agent, key)
          val.nil? ? default : val
        rescue StandardError
          opts[:default]
        end
      end
    end
  end
end
