# frozen_string_literal: true

require 'json'

module PWN
  module AI
    # Task-class model routing from pwn.yaml ai_router / model_routes.
    module Router
      TASKS = %i[summarize plan exploit_dev triage].freeze
      FRONTIER = %w[openai anthropic grok gemini].freeze
      LOCAL = %w[ollama openwebui].freeze
      ENGINE_MOD = {
        'ollama' => 'PWN::AI::Ollama',
        'openwebui' => 'PWN::AI::OpenWebUI',
        'openai' => 'PWN::AI::OpenAI',
        'anthropic' => 'PWN::AI::Anthropic',
        'grok' => 'PWN::AI::Grok',
        'gemini' => 'PWN::AI::Gemini'
      }.freeze

      public_class_method def self.required_bins
        []
      end

      # Resolve engine/model fallbacks for a task class.
      public_class_method def self.resolve(opts = {})
        task = (opts[:task] || opts[:class] || :summarize).to_s.to_sym
        entry = config_entry(task: task)
        endpoints = expand_endpoints(entry: entry)
        allow_frontier = !%i[summarize plan].include?(task)
        allow_frontier &&= entry[:allow_frontier] != false && entry['allow_frontier'] != false
        { task: task, endpoints: endpoints, allow_frontier: allow_frontier }
      end

      # Summarize text on the cheap local chain; never calls frontier models.
      public_class_method def self.summarize(opts = {})
        text = (opts[:text] || opts[:content]).to_s
        reset_task = opts[:reset_usage]
        reset_usage if reset_task
        note_usage(task: :summarize, frontier_tokens: 0)
        if opts[:llm]
          resolve(task: :summarize)[:endpoints].each do |endpoint|
            next if frontier?(engine: endpoint[:engine])

            out = try_chat(endpoint: endpoint, request: "Summarize this artifact for paging. Be terse.\n#{text.byteslice(0, 8_192)}")
            return out if out.to_s.strip != ''
          end
        end
        extractive(text: text)
      rescue StandardError
        extractive(text: text)
      end

      # Return per-task token accounting (frontier_tokens is always 0 for summarize).
      public_class_method def self.usage(opts = {})
        _n = opts[:n]
        @usage ||= {}
        @usage
      end

      # Clear the in-process usage ledger.
      public_class_method def self.reset_usage(opts = {})
        _n = opts[:n]
        @usage = {}
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # List host binaries this module expects to be installed.
          #{self}.required_bins

          # Resolve engine/model fallbacks for a task class.
          #{self}.resolve(
            task: 'optional - summarize, plan, exploit_dev, or triage',
            class: 'optional - alias for task'
          )

          # Summarize text on the cheap local chain; never calls frontier models.
          #{self}.summarize(
            text: 'optional - artifact or page text to summarize',
            content: 'optional - alias for text',
            reset_usage: 'optional - true clears the usage ledger first',
            llm: 'optional - true tries local-engine chat after skipping frontier endpoints'
          )

          # Return per-task token accounting (frontier_tokens is always 0 for summarize).
          #{self}.usage(
            n: 'optional - unused placeholder so the method reads opts'
          )

          # Clear the in-process usage ledger.
          #{self}.reset_usage(
            n: 'optional - unused placeholder so the method reads opts'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end

      private_class_method def self.config_entry(opts = {})
        task = opts[:task]
        router = env_hash(key: :ai_router)
        routes = env_dig(keys: %i[ai agent model_routes])
        raw = (router[task] || router[task.to_s] || routes[task] || routes[task.to_s]).dup
        raw = default_entry(task: task) if raw.nil? || raw == {}
        raw.is_a?(Hash) ? raw.transform_keys(&:to_sym) : { engine: raw.to_s }
      end

      private_class_method def self.default_entry(opts = {})
        task = opts[:task]
        case task
        when :exploit_dev
          { engine: 'ollama', model: 'qwen2.5-coder', fallbacks: [{ engine: 'openai' }] }
        when :summarize, :plan, :triage
          { engine: 'ollama', fallbacks: [{ engine: 'openwebui' }], allow_frontier: false }
        else
          { engine: env_dig(keys: %i[ai active]).to_s }
        end
      end

      private_class_method def self.expand_endpoints(opts = {})
        entry = opts[:entry]
        head = { engine: (entry[:engine] || entry[:endpoint] || 'ollama').to_s, model: entry[:model] }
        rest = Array(entry[:fallbacks] || entry[:fallback]).map do |item|
          item.is_a?(Hash) ? item.transform_keys(&:to_sym) : { engine: item.to_s }
        end
        ([head] + rest).map { |row| { engine: row[:engine].to_s.downcase, model: row[:model] } }
      end

      private_class_method def self.frontier?(opts = {})
        FRONTIER.include?(opts[:engine].to_s.downcase)
      end

      private_class_method def self.try_chat(opts = {})
        endpoint = opts[:endpoint]
        engine = endpoint[:engine].to_s
        const = ENGINE_MOD[engine]
        return nil unless const

        mod = Object.const_get(const)
        return nil unless mod.respond_to?(:chat)

        resp = mod.chat(request: opts[:request], model: endpoint[:model], spinner: false, quiet: true, timeout: 8)
        text = resp.is_a?(Hash) ? (resp[:content] || resp['content'] || resp.dig(:choices, 0, :content)).to_s : resp.to_s
        text.strip.empty? ? nil : text
      rescue StandardError
        nil
      end

      private_class_method def self.extractive(opts = {})
        text = opts[:text].to_s
        text.byteslice(0, 2_048).to_s
      end

      private_class_method def self.note_usage(opts = {})
        task = opts[:task].to_sym
        @usage ||= {}
        @usage[task] ||= { frontier_tokens: 0, local_tokens: 0 }
        @usage[task][:frontier_tokens] = opts[:frontier_tokens].to_i if opts.key?(:frontier_tokens)
        @usage[task][:local_tokens] += opts[:local_tokens].to_i if opts[:local_tokens]
      end

      private_class_method def self.env_hash(opts = {})
        return {} unless defined?(PWN::Env)

        val = PWN::Env[opts[:key]]
        if val.is_a?(Hash)
          val.transform_keys { |key| key.is_a?(String) ? key.to_sym : key }
        else
          {}
        end
      rescue StandardError
        {}
      end

      private_class_method def self.env_dig(opts = {})
        return {} unless defined?(PWN::Env) && PWN::Env.respond_to?(:dig)

        val = PWN::Env.dig(*opts[:keys])
        if val.is_a?(Hash)
          val.transform_keys { |key| key.is_a?(String) ? key.to_sym : key }
        else
          val
        end
      rescue StandardError
        {}
      end
    end
  end
end
