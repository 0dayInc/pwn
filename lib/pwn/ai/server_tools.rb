# frozen_string_literal: true

require 'json'

module PWN
  module AI
    # Provider-hosted tools, separate from PWN::AI::Agent::Registry.
    #
    # Open WebUI is the only engine here with a user-installed tool workspace.
    # Ask Jev is one of those tools. The other engines either run a fixed set of
    # hosted tools on their own API, or they have no server-side tool surface.
    module ServerTools
      OPENAI = {
        'web_search' => { type: 'web_search' },
        'code_interpreter' => { type: 'code_interpreter' }
      }.freeze
      ANTHROPIC = {
        'web_search' => { type: 'web_search_20250305', name: 'web_search' },
        'web_fetch' => { type: 'web_fetch_20250910', name: 'web_fetch' }
      }.freeze
      GEMINI = {
        'google_search' => { googleSearch: {} }
      }.freeze
      GROK = {
        'web_search' => { type: 'web_search' },
        'x_search' => { type: 'x_search' },
        'code_interpreter' => { type: 'code_interpreter' }
      }.freeze
      WIRE = { openai: OPENAI, anthropic: ANTHROPIC, gemini: GEMINI, grok: GROK }.freeze

      # Supported Method Parameters::
      # row = PWN::AI::ServerTools.catalog(
      #   engine: 'required - openai, anthropic, gemini, grok, ollama, or openwebui'
      # )
      public_class_method def self.catalog(opts = {})
        engine = opts[:engine].to_s.downcase.to_sym
        {
          engine: engine,
          workspace: engine == :openwebui,
          mixable: mixable?(engine: engine, model: opts[:model]),
          tools: engine == :openwebui ? [] : Array(WIRE[engine]).map { |name, _wire| name }
        }
      end

      # Supported Method Parameters::
      # rows = PWN::AI::ServerTools.list(
      #   engine: 'required - provider name',
      #   refresh: 'optional - true re-reads the Open WebUI workspace tool list',
      #   model: 'optional - used to decide whether OpenAI hosted tools share the request'
      # )
      public_class_method def self.list(opts = {})
        engine = opts[:engine].to_s.downcase.to_sym
        return PWN::AI::OpenWebUI.workspace_tools(refresh: opts[:refresh]) if engine == :openwebui

        catalog(engine: engine, model: opts[:model])[:tools]
      end

      # Supported Method Parameters::
      # objects = PWN::AI::ServerTools.wire(
      #   engine: 'required - provider name',
      #   names: 'required - hosted tool names such as web_search or google_search'
      # )
      public_class_method def self.wire(opts = {})
        engine = opts[:engine].to_s.downcase.to_sym
        table = WIRE[engine] || {}
        Array(opts[:names]).map do |name|
          row = table[name.to_s]
          raise ArgumentError, "#{engine} has no hosted tool #{name}" unless row

          row.dup
        end
      end

      # Supported Method Parameters::
      # same = PWN::AI::ServerTools.mixable?(
      #   engine: 'required - provider name',
      #   model: 'optional - OpenAI model id; hosted tools share only a Responses request'
      # )
      public_class_method def self.mixable?(opts = {})
        engine = opts[:engine].to_s.downcase.to_sym
        return false unless %i[anthropic gemini openai].include?(engine)
        return true unless engine == :openai

        PWN::AI::OpenAI.api_endpoint(model: opts[:model]) == 'responses'
      end

      # Supported Method Parameters::
      # body = PWN::AI::ServerTools.attach(
      #   engine: 'required - provider name',
      #   http_body: 'required - provider request body',
      #   request: 'required - original chat options, including server_tools'
      # )
      public_class_method def self.attach(opts = {})
        body = opts[:http_body]
        names = selected(request: opts[:request])
        return body if names.empty?

        engine = opts[:engine].to_s.downcase.to_sym
        hosted = wire(engine: engine, names: names)
        case engine
        when :anthropic, :gemini, :openai
          raise ArgumentError, 'OpenAI hosted tools require the Responses API' if engine == :openai && !body.key?(:input)

          body[:tools] = Array(body[:tools]) + hosted
        else
          raise ArgumentError, "#{engine} cannot mix hosted tools into this request"
        end
        body
      end

      # Supported Method Parameters::
      # result = PWN::AI::ServerTools.call(
      #   name: 'required - workspace tool name or hosted tool name',
      #   request: 'required - question or state to send with that tool',
      #   engine: 'optional - provider name; Ask Jev uses Open WebUI when that provider is configured',
      #   model: 'optional - overrides the provider model'
      # )
      public_class_method def self.call(opts = {})
        name = opts[:name].to_s.strip
        request = opts[:request].to_s
        raise ArgumentError, 'request is required' if request.strip.empty?

        engine = route(name: name, engine: opts[:engine])
        return { available: false, engine: engine, reason: 'Ollama has no server-side tool workspace' } if engine == :ollama
        return openwebui_call(name: name, request: request, model: opts[:model]) if engine == :openwebui

        mod = Object.const_get(PWN::AI::Agent::Reflect::ENGINE_MODS.fetch(engine))
        response = mod.chat_with_tools(
          messages: [{ role: 'user', content: request }],
          server_tools: [name],
          model: opts[:model],
          spinner: false
        )
        { available: true, engine: engine, name: name, content: answer_text(response: response) }
      end

      public_class_method def self.authors
        "AUTHOR(S):\n          0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Describe whether an engine has a workspace or only fixed hosted tools.
          #{self}.catalog(
            engine: 'required - openai, anthropic, gemini, grok, ollama, or openwebui',
            model: 'optional - OpenAI model id used only to report whether hosted tools can share the request'
          )

          # List hosted tool names, or the installed Open WebUI workspace tools.
          #{self}.list(
            engine: 'required - provider name',
            refresh: 'optional - true re-reads the Open WebUI workspace tool list',
            model: 'optional - used to decide whether OpenAI hosted tools share the request'
          )

          # Translate hosted tool names into that provider's request objects.
          #{self}.wire(
            engine: 'required - provider name',
            names: 'required - hosted tool names such as web_search or google_search'
          )

          # True when hosted tools can share the same request as Registry client tools.
          #{self}.mixable?(
            engine: 'required - provider name',
            model: 'optional - OpenAI model id; hosted tools share only a Responses request'
          )

          # Append hosted tool objects to a provider body. Open WebUI is not mixed here.
          #{self}.attach(
            engine: 'required - provider name',
            http_body: 'required - provider request body',
            request: 'required - original chat options, including server_tools'
          )

          # Run one server-side tool and return its answer. Ask Jev uses Open WebUI.
          #{self}.call(
            name: 'required - workspace tool name or hosted tool name',
            request: 'required - question or state to send with that tool',
            engine: 'optional - provider name; Ask Jev uses Open WebUI when that provider is configured',
            model: 'optional - overrides the provider model'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
      end

      private_class_method def self.selected(opts = {})
        Array(opts.dig(:request, :server_tools)).map(&:to_s).reject(&:empty?)
      end

      private_class_method def self.route(opts = {})
        name = opts[:name].to_s
        engine = opts[:engine].to_s.downcase
        engine = PWN::Env.dig(:ai, :active).to_s.downcase if engine.empty? && defined?(PWN::Env)
        return :openwebui if name.match?(/ask[[:space:]]*jev/i) && openwebui_ready?

        engine.empty? ? :openwebui : engine.to_sym
      end

      private_class_method def self.openwebui_ready?
        engine = PWN::Env.dig(:ai, :openwebui) if defined?(PWN::Env)
        return false unless engine.is_a?(Hash)

        PWN::AI::OpenWebUI.send(:real_config_value?, value: engine[:base_uri]) &&
          PWN::AI::OpenWebUI.send(:real_config_value?, value: engine[:key])
      rescue StandardError
        false
      end

      private_class_method def self.openwebui_call(opts = {})
        name = opts[:name].to_s
        listed = PWN::AI::OpenWebUI.workspace_tools
        return { available: true, engine: :openwebui, tools: listed } if name.empty?

        response = PWN::AI::OpenWebUI.chat(request: opts[:request], server_tools: [name], model: opts[:model], spinner: false)
        { available: true, engine: :openwebui, name: name, content: answer_text(response: response), sources: response[:sources] || response['sources'] }
      end

      private_class_method def self.answer_text(opts = {})
        response = opts[:response]
        return '' unless response.is_a?(Hash)

        message = response[:assistant_message] || response.dig(:choices, -1)
        message = message[:message] if message.is_a?(Hash) && message[:message]
        text = message.is_a?(Hash) ? (message[:content] || message['content']) : nil
        text.to_s
      end
    end
  end
end
