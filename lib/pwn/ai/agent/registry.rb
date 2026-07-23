# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # Central registry for pwn-ai agent tools.
      #
      # Each file under lib/pwn/ai/agent/tools/*.rb calls
      # +PWN::AI::Agent::Registry.register(...)+ at load time to declare a
      # JSON-Schema (what the LLM sees) and a handler lambda (what pwn runs).
      #
      # Registry.definitions(...) returns the OpenAI-format +tools:+ array;
      # Registry.lookup(name:) returns the entry for dispatch.
      #
      # Import chain (circular-import safe):
      #   agent/registry.rb        (no deps on tool files)
      #          ^
      #   agent/tools/*.rb         (require registry, call .register at top level)
      #          ^
      #   agent/loop.rb            (calls Registry.discover then .definitions)
      #
      # DYNAMIC TOOL-SET SLIMMING (local-model scaffolding)
      # ---------------------------------------------------
      # Shipping all ~47 tool schemas on every call overwhelms a 35B local
      # model — it mis-routes (extro_rf_tune for a git question) because the
      # choice space is huge. When PWN::Env[:ai][:agent][:tool_router] is
      # truthy (or nil while active==:ollama) AND definitions(relevance:)
      # is passed, the pool is
      # reduced to CORE_TOOLS + the top-K keyword-ranked matches. Routing
      # accuracy is fed back into Metrics under name:'tool_router' so the
      # router itself becomes a learned component.
      module Registry
        Entry = Struct.new(
          :name,        # String  - tool name exposed to the model
          :toolset,     # String  - grouping for enable/disable (terminal, file, pwn, memory…)
          :schema,      # Hash    - OpenAI function schema {name:, description:, parameters:}
          :handler,     # Proc    - ->(args_hash) { ... } returning a JSON-serialisable object
          :check,       # Proc    - -> { bool } gate; tool only advertised when truthy
          :max_chars,   # Integer - cap on serialised result before it re-enters the convo
          keyword_init: true
        )

        CORE_TOOLS = %w[shell pwn_eval memory_remember memory_recall
                        mistakes_record mistakes_resolve learning_note_outcome].freeze

        @entries = {}
        @discovered = false

        # Supported Method Parameters::
        # PWN::AI::Agent::Registry.register(
        #   name: 'required - tool name exposed to the model',
        #   toolset: 'required - grouping for enable/disable (terminal, file, pwn, memory…)',
        #   schema: 'required - OpenAI function schema {name:, description:, parameters:}',
        #   handler: 'required - ->(args_hash) { ... } returning a JSON-serialisable object',
        #   check: 'optional - -> { bool } gate; tool only advertised when truthy',
        #   max_chars: 'optional - cap on serialised result (default 24_000)'
        # )

        public_class_method def self.register(opts = {})
          name = opts[:name].to_s
          raise 'ERROR: name is required' if name.empty?
          raise 'ERROR: schema is required' unless opts[:schema]
          raise 'ERROR: handler is required' unless opts[:handler].respond_to?(:call)

          @entries[name] = Entry.new(
            name: name,
            toolset: opts[:toolset].to_s,
            schema: opts[:schema],
            handler: opts[:handler],
            check: opts[:check] ||= -> { true },
            max_chars: opts[:max_chars] ||= 24_000
          )
        end

        # Supported Method Parameters::
        # entry = PWN::AI::Agent::Registry.lookup(
        #   name: 'required - registered tool name'
        # )

        public_class_method def self.lookup(opts = {})
          name = opts[:name]
          @entries[name.to_s]
        end

        # Supported Method Parameters::
        # entries = PWN::AI::Agent::Registry.all

        public_class_method def self.all
          @entries.values
        end

        # Supported Method Parameters::
        # names = PWN::AI::Agent::Registry.toolsets

        public_class_method def self.toolsets
          @entries.values.map(&:toolset).uniq.sort
        end

        # Supported Method Parameters::
        # tools = PWN::AI::Agent::Registry.definitions(
        #   enabled: 'optional - Array of toolset names to include; nil = all whose check passes',
        #   relevance: 'optional - user request; when set AND :tool_router is enabled, slim to CORE + top-K keyword matches',
        #   top_k: 'optional - keyword-ranked tools to keep beyond CORE (default 10)'
        # )

        public_class_method def self.definitions(opts = {})
          enabled = opts[:enabled]
          enabled = enabled.map(&:to_s) if enabled
          pool = @entries.values.select { |e| (enabled.nil? || enabled.include?(e.toolset)) && safe_check(entry: e) }

          if opts[:relevance] && router_enabled?
            keep  = rank(query: opts[:relevance], entries: pool).first(opts[:top_k] || 10).map(&:name)
            names = (CORE_TOOLS + keep).uniq
            pool  = pool.select { |e| names.include?(e.name) }
          end

          pool.map { |e| { type: 'function', function: e.schema } }
        end

        # Supported Method Parameters::
        # ranked = PWN::AI::Agent::Registry.rank(
        #   query: 'required - user request text',
        #   entries: 'optional - Entry pool to rank (default .all)'
        # )
        #
        # C1 advantage-weighted router: score = α·keyword_sim + β·(tool
        # rolling success_rate − global rate) + γ·UCB1(tool). Untried tools
        # get an exploration bonus; tools that outperform the fleet get an
        # exploitation bonus. Thompson sampling is available via
        # Metrics.thompson for stochastic routing.

        public_class_method def self.rank(opts = {})
          query   = opts[:query].to_s.downcase
          entries = opts[:entries] || all
          return entries if query.strip.empty?

          tokens = query.scan(/[a-z0-9_]{3,}/).uniq
          # C1 — advantage-weighted router:
          #   score = α·keyword_sim + β·advantage + γ·UCB(tool)
          # UCB gives untried / low-N tools an exploration bonus so a single
          # early failure (before its dep was installed) does not blacklist
          # it forever; advantage prefers tools that outperform the fleet.
          alpha = 1.0
          # P4 — haircut advantage weight when reward proxy is hacked
          trust = defined?(Metrics) && Metrics.respond_to?(:proxy_trust) ? Metrics.proxy_trust : 1.0
          beta  = 0.3 * trust
          gamma = 0.2
          scored = entries.map do |e|
            hay   = "#{e.name} #{e.toolset} #{e.schema[:description]} #{Array(e.schema.dig(:parameters, :properties)&.keys).join(' ')}".downcase
            sim   = tokens.count { |t| hay.include?(t) }
            adv   = defined?(Metrics) && Metrics.respond_to?(:advantage) ? Metrics.advantage(name: e.name) : 0.0
            ucb   = defined?(Metrics) && Metrics.respond_to?(:ucb) ? Metrics.ucb(name: e.name) : 0.5
            [e, sim, (alpha * sim) + (beta * adv) + (gamma * ucb)]
          end
          scored.reject { |_, sim, _| sim.zero? }
                .sort_by { |_, _, s| -s }
                .map(&:first)
        end

        # Supported Method Parameters::
        # names = PWN::AI::Agent::Registry.discover(
        #   force: 'optional - re-require tool files even if already discovered (default false)'
        # )

        public_class_method def self.discover(opts = {})
          force = opts[:force] ||= false
          return @entries.keys if @discovered && !force

          tools_dir = File.join(__dir__, 'tools')
          if Dir.exist?(tools_dir)
            Dir[File.join(tools_dir, '*.rb')].each do |f|
              require f
            rescue StandardError, LoadError => e
              warn "[pwn-ai] failed to load tool #{File.basename(f)}: #{e.class}: #{e.message}"
            end
          end
          @discovered = true
          @entries.keys
        end

        private_class_method def self.safe_check(opts = {})
          entry = opts[:entry]
          entry.check.call
        rescue StandardError
          false
        end

        private_class_method def self.router_enabled?
          return false unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          v = PWN::Env.dig(:ai, :agent, :tool_router)
          # nil = auto: on for ollama (largest single local-model win — ~11k→~3k
          # schema tokens/turn); off for frontier unless explicitly enabled.
          return v ? true : false unless v.nil?

          PWN::Env.dig(:ai, :active).to_s.downcase.to_sym == :ollama
        rescue StandardError
          false
        end

        private_class_method def self.metrics_rates
          return {} unless defined?(Metrics)

          Metrics.summary(limit: 200).to_h { |r| [r[:name], r[:success_rate]] }
        rescue StandardError
          {}
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::Registry.discover
              PWN::AI::Agent::Registry.definitions(enabled: %w[terminal pwn])
              PWN::AI::Agent::Registry.definitions(relevance: 'nmap sweep 10/8')  # slim (needs :tool_router)
              PWN::AI::Agent::Registry.rank(query: 'run a shell command')
              PWN::AI::Agent::Registry.lookup(name: 'shell')   # => Entry
              PWN::AI::Agent::Registry.toolsets                # => ["memory","pwn","skills","terminal"]
              PWN::AI::Agent::Registry.register(name:, toolset:, schema:, handler:)

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
