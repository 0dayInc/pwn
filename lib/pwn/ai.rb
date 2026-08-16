# frozen_string_literal: true

module PWN
  # This file, using the autoload directive loads AI modules
  # into memory only when they're needed. For more information, see:
  # http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html
  module AI
    autoload :Agent, 'pwn/ai/agent'
    autoload :Anthropic, 'pwn/ai/anthropic'
    autoload :Gemini, 'pwn/ai/gemini'
    autoload :Grok, 'pwn/ai/grok'
    autoload :Ollama, 'pwn/ai/ollama'
    autoload :OpenAI, 'pwn/ai/open_ai'
    autoload :OpenWebUI, 'pwn/ai/open_web_ui'
    autoload :RedTeam, 'pwn/ai/red_team'

    PLAN_USAGE_CACHE_TTL = 60
    PLAN_USAGE_INFINITY = "\u221E"
    ENGINE_MODULES = {
      openai: 'PWN::AI::OpenAI',
      grok: 'PWN::AI::Grok',
      ollama: 'PWN::AI::Ollama',
      openwebui: 'PWN::AI::OpenWebUI',
      anthropic: 'PWN::AI::Anthropic',
      gemini: 'PWN::AI::Gemini'
    }.freeze

    # Supported Method Parameters::
    # usage = PWN::AI.normalize_plan_usage(
    #   used: 'required - numeric used amount',
    #   limit: 'required - numeric limit / allowance',
    #   source: 'optional - endpoint / origin label',
    #   engine: 'optional - engine symbol'
    # )
    public_class_method def self.normalize_plan_usage(opts = {})
      used = opts[:used]
      limit = opts[:limit]
      used_f = used&.to_f
      limit_f = limit&.to_f
      available = !used_f.nil? && !limit_f.nil? && limit_f.positive?
      percent = available ? ((used_f / limit_f) * 100.0).round : nil
      percent = 0 if percent && percent.negative?
      percent = 100 if percent && percent > 100
      {
        available: available,
        used: used_f,
        limit: limit_f,
        percent: percent,
        source: opts[:source],
        engine: opts[:engine]
      }
    end

    # Supported Method Parameters::
    # usage = PWN::AI.plan_usage(
    #   engine: 'optional - engine symbol (defaults to PWN::Env[:ai][:active])',
    #   ttl: 'optional - cache seconds (default 60)',
    #   force: 'optional - bypass cache (default false)'
    # )
    public_class_method def self.plan_usage(opts = {})
      engine = (opts[:engine] || PWN::Env.dig(:ai, :active)).to_s.downcase.to_sym
      ttl = (opts[:ttl] || PLAN_USAGE_CACHE_TTL).to_i
      ttl = PLAN_USAGE_CACHE_TTL if ttl <= 0
      cache = (@plan_usage_cache ||= {})
      now = Time.now.to_i
      hit = cache[engine]
      return hit[:value] if !opts[:force] && hit.is_a?(Hash) && (now - hit[:at].to_i) < ttl

      klass_name = ENGINE_MODULES[engine]
      value = { available: false, engine: engine }
      if klass_name
        begin
          klass = Object.const_get(klass_name)
          value = klass.get_plan_usage if klass.respond_to?(:get_plan_usage)
          value = { available: false, engine: engine } unless value.is_a?(Hash)
          value[:engine] ||= engine
        rescue StandardError
          value = { available: false, engine: engine }
        end
      end
      cache[engine] = { at: now, value: value }
      value
    end

    # Supported Method Parameters::
    # glyph = PWN::AI.plan_usage_glyph(
    #   engine: 'optional - engine symbol (defaults to PWN::Env[:ai][:active])',
    #   usage: 'optional - precomputed usage hash'
    # )
    #
    # Returns "19%" when used/limit are known, otherwise the infinity glyph.
    # Local engines (ollama / openwebui) always return infinity.
    public_class_method def self.plan_usage_glyph(opts = {})
      engine = (opts[:engine] || PWN::Env.dig(:ai, :active)).to_s.downcase.to_sym
      return PLAN_USAGE_INFINITY if %i[ollama openwebui].include?(engine)

      usage = opts[:usage] || plan_usage(engine: engine)
      return PLAN_USAGE_INFINITY unless usage.is_a?(Hash) && usage[:available] && !usage[:percent].nil?

      "#{usage[:percent].to_i}%"
    end

    # Display a List of Every PWN::AI Module

    # Author(s):: 0day Inc. <support@0dayinc.com>

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      constants.sort
    end
  end
end
