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
        #   enabled: 'optional - Array of toolset names to include; nil = all whose check passes'
        # )

        public_class_method def self.definitions(opts = {})
          enabled = opts[:enabled]
          enabled = enabled.map(&:to_s) if enabled
          @entries.values
                  .select { |e| (enabled.nil? || enabled.include?(e.toolset)) && safe_check(entry: e) }
                  .map    { |e| { type: 'function', function: e.schema } }
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
