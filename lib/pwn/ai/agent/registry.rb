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

        CORE_TOOLS = %w[memory_recall session_recall skills_recall pwn_eval shell
                        mistakes_record mistakes_resolve learning_note_outcome
                        memory_remember skills_update].freeze

        # Schema order = CORE_TOOLS. Current session is injected (RECENT TURNS).
        # Then memory / prior sessions / skills, then pwn_eval before shell.
        # opts[:preference], or PWN::Env[:ai][:agent][:tool_preference].
        # Explicit nil/empty order disables preference (no Env/DEFAULT fallback).
        DEFAULT_PREFERENCE = CORE_TOOLS

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
        #   top_k: 'optional - keyword-ranked tools to keep beyond CORE (default 10)',
        #   order: 'optional - preference list forwarded only when this key is present',
        #   preference: 'optional - alias of :order; same key-present rule'
        # )

        public_class_method def self.definitions(opts = {})
          enabled = opts[:enabled]
          enabled = enabled.map(&:to_s) if enabled
          pool = @entries.values.select { |e| (enabled.nil? || enabled.include?(e.toolset)) && safe_check(entry: e) }

          pref_fwd = {}
          pref_fwd[:order] = opts[:order] if opts.key?(:order)
          pref_fwd[:preference] = opts[:preference] if opts.key?(:preference)
          pref_fwd[:kind] = opts[:kind] if opts.key?(:kind)
          pref_fwd[:intent] = opts[:intent] if opts.key?(:intent)

          if opts[:core_only]
            pool = pool.select { |e| CORE_TOOLS.include?(e.name) }
          elsif opts[:relevance] && router_enabled?
            keep = rank({ query: opts[:relevance], entries: pool }.merge(pref_fwd)).first(opts[:top_k] || 10).map(&:name)
            names = (CORE_TOOLS + keep).uniq
            pool  = pool.select { |e| names.include?(e.name) }
          end

          pool = apply_preference({ items: pool }.merge(pref_fwd))
          pool.map { |e| { type: 'function', function: e.schema } }
        end

        # Supported Method Parameters::
        # order = PWN::AI::Agent::Registry.preference_order(
        #   order: 'optional - Array of tool names; explicit nil/[] disables',
        #   preference: 'optional - alias of :order. Explicit key disables Env/DEFAULT fallback'
        # )

        public_class_method def self.preference_order(opts = {})
          explicit = opts.key?(:order) || opts.key?(:preference)
          if explicit
            raw = opts.key?(:preference) ? opts[:preference] : opts[:order]
            return [] if raw.nil? || (raw.respond_to?(:empty?) && raw.empty?)

            return Array(raw).map(&:to_s).reject(&:empty?)
          end

          raw = nil
          raw = PWN::Env.dig(:ai, :agent, :tool_preference) if defined?(PWN::Env) && PWN::Env.is_a?(Hash)
          return Array(raw).map(&:to_s).reject(&:empty?) unless raw.nil? || (raw.respond_to?(:empty?) && raw.empty?)

          DEFAULT_PREFERENCE.dup
        rescue StandardError
          DEFAULT_PREFERENCE.dup
        end

        # Supported Method Parameters::
        # sorted = PWN::AI::Agent::Registry.apply_preference(
        #   items: 'required - Array of Entry objects or OpenAI tool hashes',
        #   order: 'optional - forwarded to preference_order only when the key is set',
        #   preference: 'optional - alias of :order; same key-present rule'
        # )
        #
        # Stable sort: preferred names first, original index as the tie-break
        # so equal-preference items keep their incoming order.
        # Empty preference (explicit [] / nil) leaves items unsorted.

        public_class_method def self.apply_preference(opts = {})
          items = Array(opts[:items] || opts[:entries])
          po = {}
          po[:preference] = opts[:preference] if opts.key?(:preference)
          po[:order] = opts[:order] if opts.key?(:order)
          order = preference_order(po)
          return items if order.empty?

          index = {}
          order.each_with_index { |name, i| index[name.to_s] = i }
          fallback = order.length
          items.sort_by.with_index do |item, orig|
            name = if item.respond_to?(:name)
                     item.name.to_s
                   elsif item.is_a?(Hash)
                     (item.dig(:function, :name) ||
                      item.dig('function', 'name') ||
                      item[:name] || item['name']).to_s
                   else
                     item.to_s
                   end
            [index.fetch(name, fallback), orig]
          end
        end

        # Supported Method Parameters::
        # ranked = PWN::AI::Agent::Registry.rank(
        #   query: 'required - user request text',
        #   entries: 'optional - Entry pool to rank (default .all)',
        #   order: 'optional - preference list forwarded to preference_order'
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
          #   score = alpha*keyword_sim + beta*advantage + gamma*UCB(tool)
          #         + delta*prm_advantage + eps_q*Q_adv + zeta*pref_score
          # UCB gives untried / low-N tools an exploration bonus so a single
          # early failure (before its dep was installed) does not blacklist
          # it forever; advantage prefers tools that outperform the fleet.
          # zeta * pref_score (zeta=0.35) boosts Env/opts tool preference;
          # alpha stays 1.0 so keyword fit remains the primary signal.
          # zeta is 0 when preference is empty so ties are not pref-boosted.
          alpha = 1.0
          po = {}
          po[:preference] = opts[:preference] if opts.key?(:preference)
          po[:order] = opts[:order] if opts.key?(:order)
          pref_order = preference_order(po)
          zeta = pref_order.empty? ? 0.0 : 0.35
          pref_index = {}
          pref_order.each_with_index { |n, i| pref_index[n.to_s] = i }
          pref_n = [pref_order.length, 1].max
          # P4 — haircut advantage weight when reward proxy is hacked
          trust = defined?(Metrics) && Metrics.respond_to?(:proxy_trust) ? Metrics.proxy_trust : 1.0
          beta  = 0.3 * trust
          gamma = 0.2
          # P18/P2 — PRM step_reward advantage closes R2 into the controller.
          # Sample-efficiency: if fewer than 3 tools have prm_n≥PRM_MIN_N,
          # drop delta to 0 so sparse PRM cannot inject rank variance.
          # Otherwise scale delta by fleet coverage fraction.
          prm_ready = 0
          if defined?(Metrics) && Metrics.respond_to?(:prm_n)
            prm_ready = entries.count do |e|
              Metrics.prm_n(name: e.name).to_i >= begin
                Metrics::PRM_MIN_N
              rescue StandardError
                5
              end
            end
          end
          fleet = [entries.length, 1].max
          coverage = prm_ready.to_f / fleet
          delta = if prm_ready < 3
                    0.0
                  else
                    0.25 * trust * [coverage / 0.3, 1.0].min
                  end
          # R5 — tabular Q(s,a)−V(s). Weight sits next to Metrics advantage
          # so a warm table actually moves rank. Keyword fit stays first
          # (alpha=1.0); CORE_TOOLS still always included.
          eps_q = if defined?(PWN::AI::Agent::Policy) && Policy.respond_to?(:advantage) && Policy.respond_to?(:enabled?) && Policy.enabled?
                    warm = Policy.respond_to?(:episode_budget_met?) && Policy.episode_budget_met?
                    (warm ? 0.45 : 0.20) * [trust, 0.55].max
                  else
                    0.0
                  end
          pol_state = (Policy.current_state || Policy.state(request: query) if defined?(PWN::AI::Agent::Policy) && Policy.respond_to?(:current_state))
          scored = entries.map do |e|
            hay   = "#{e.name} #{e.toolset} #{e.schema[:description]} #{Array(e.schema.dig(:parameters, :properties)&.keys).join(' ')}".downcase
            sim   = tokens.count { |t| hay.include?(t) }
            adv   = defined?(Metrics) && Metrics.respond_to?(:advantage) ? Metrics.advantage(name: e.name) : 0.0
            ucb   = defined?(Metrics) && Metrics.respond_to?(:ucb) ? Metrics.ucb(name: e.name) : 0.5
            prm   = defined?(Metrics) && Metrics.respond_to?(:prm_advantage) ? Metrics.prm_advantage(name: e.name) : 0.0
            qadv  = if eps_q.positive? && pol_state
                      Policy.advantage(state: pol_state, action: e.name)
                    else
                      0.0
                    end
            pidx = pref_index[e.name]
            pref = pidx.nil? ? 0.0 : ((pref_n - pidx).to_f / pref_n)
            total = (alpha * sim) + (beta * adv) + (gamma * ucb) + (delta * prm) + (eps_q * qadv) + (zeta * pref)
            [e, sim, total]
          end
          # Equal keyword-fit (and equal total): preferred name first.
          scored.reject { |_, sim, _| sim.zero? }
                .sort_by { |e, _, s| [-s, pref_index.fetch(e.name, pref_n), e.name] }
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
          # nil = auto ON for every engine: ~85 tools / ~50KB schemas bloat every
          # turn (esp. Grok). Opt out with tool_router: false.
          return !!v unless v.nil?

          true
        rescue StandardError
          true
        end

        private_class_method def self.metrics_rates
          return {} unless defined?(Metrics)

          Metrics.summary(limit: 200).to_h { |r| [r[:name], r[:effective_rate] || r[:success_rate]] }
        rescue StandardError
          {}
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Run register and return its result
            #{self}.register(
              name: 'required - tool name exposed to the model',
              toolset: 'required - grouping for enable/disable (terminal, file, pwn, memory…)',
              schema: 'required - OpenAI function schema {name:, description:, parameters:}',
              handler: 'required - ->(args_hash) { ... } returning a JSON-serialisable object',
              check: 'optional - -> { bool } gate; tool only advertised when truthy',
              max_chars: 'optional - cap on serialised result (default 24_000)'
            )

            # Run lookup and return its result
            #{self}.lookup(
              name: 'required - registered tool name'
            )

            # Run all and return its result
            #{self}.all

            # Run toolsets and return its result
            #{self}.toolsets

            # Run definitions and return its result
            #{self}.definitions(
              enabled: 'optional - Array of toolset names to include; nil = all whose check passes',
              relevance: 'optional - user request; when set AND :tool_router is enabled, slim to CORE + top-K keyword matches',
              top_k: 'optional - keyword-ranked tools to keep beyond CORE (default 10)',
              order: 'optional - preference list forwarded only when this key is present',
              preference: 'optional - alias of :order; same key-present rule',
              kind: 'optional - kind value consumed by #definitions',
              intent: 'optional - intent value consumed by #definitions',
              core_only: 'optional - core only value consumed by #definitions'
            )

            # Run preference order and return its result
            #{self}.preference_order(
              order: 'optional - Array of tool names; explicit nil/[] disables',
              preference: 'optional - alias of :order. Explicit key disables Env/DEFAULT fallback'
            )

            # Run apply preference and return its result
            #{self}.apply_preference(
              items: 'required - Array of Entry objects or OpenAI tool hashes',
              order: 'optional - forwarded to preference_order only when the key is set',
              preference: 'optional - alias of :order; same key-present rule',
              entries: 'optional - entries value consumed by #apply_preference'
            )

            # Run rank and return its result
            #{self}.rank(
              query: 'required - user request text',
              entries: 'optional - Entry pool to rank (default .all)',
              order: 'optional - preference list forwarded to preference_order',
              preference: 'optional - preference value consumed by #rank'
            )

            # Run discover and return its result
            #{self}.discover(
              force: 'optional - re-require tool files even if already discovered (default false)'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
