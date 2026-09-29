# frozen_string_literal: true

module PWN
  module Plugins
    module REPL
      # Live slash-command parameter completion. Never calls a provider.
      module AIConsoleCommands
        COMMANDS = %w[
          /back /clear /cron /debug /delegate /help /input /learning /mcp /memory /menu /model /system-role
          /sessions /skills /status /steer /swarm /trace /verbose
        ].freeze
        SWARM = %w[dashboard help roster status create use spawn retire ask debate broadcast tail steer cancel].freeze

        public_class_method def self.complete(opts = {})
          line = opts[:line].to_s
          cursor = opts[:cursor].to_i
          tokens = scan(line: line, cursor: cursor)
          current = tokens.find { |token| token[:current] } || tokens.last || { text: '', start: 0, finish: 0 }
          prefix = line.scan(/\X/)[current[:start]...cursor].to_a.join
          values, hint = if prefix.start_with?('PWN')
                           pwn_constants(prefix: prefix)
                         elsif path_token?(prefix: prefix)
                           paths(prefix: prefix)
                         else
                           candidates(tokens: tokens, prefix: prefix, pry: opts[:pry], swarm: opts[:swarm])
                         end
          items = values.map do |value|
            replacement = line_replace(line: line, token: current, value: value)
            { label: value, text: replacement[:text], cursor: replacement[:cursor] }
          end
          { items: items, hint: hint }
        end

        public_class_method def self.authors
          'AUTHOR(S): 0day Inc. <support@0dayinc.com>'
        end

        public_class_method def self.help
          puts "USAGE:
            # Complete the token at a grapheme cursor. Returned text replaces the whole line.
            #{self}.complete(
              line: 'required - current mission text',
              cursor: 'optional - grapheme index, default 0',
              pry: 'optional - Pry instance for Ruby completion',
              swarm: 'optional - controller exposing completion_context'
            )

            # Return module authors.
            #{self}.authors
          "
        end

        private_class_method def self.path_token?(opts = {})
          prefix = opts[:prefix].to_s
          return true if prefix.match?(%r{\A(?:~|\./|\.\./)})
          return false unless prefix.start_with?('/')
          return false if COMMANDS.any? { |cmd| cmd.start_with?(prefix) || prefix == cmd }

          prefix.count('/') > 1 || File.directory?(prefix)
        end

        private_class_method def self.pwn_constants(opts = {})
          prefix = opts[:prefix].to_s
          parts = prefix.split('::', -1)
          mod = Object
          parts[0..-2].each do |name|
            return [[], 'PWN constant'] unless mod.respond_to?(:const_defined?) && mod.const_defined?(name, false)

            mod = mod.const_get(name, false)
          end
          return [[], 'PWN constant'] unless mod.is_a?(Module)

          stem = parts.last.to_s
          parent = parts[0..-2].reject(&:empty?).join('::')
          names = mod.constants(false).sort.select { |name| name.to_s.start_with?(stem) }.filter_map do |name|
            shown = parent.empty? ? name.to_s : "#{parent}::#{name}"
            shown += '::' if mod.autoload?(name) || mod.const_get(name, false).is_a?(Module)
            shown
          rescue StandardError
            nil
          end
          [names, 'PWN constant']
        rescue NameError, LoadError
          [[], 'PWN constant unavailable']
        end

        private_class_method def self.paths(opts = {})
          prefix = opts[:prefix].to_s
          [REPL.pwn_ai_complete_path(target: prefix, line: prefix).first(12), 'path']
        rescue StandardError
          [[], 'path']
        end

        private_class_method def self.scan(opts = {})
          graphemes = opts[:line].scan(/\X/)
          cursor = opts[:cursor].clamp(0, graphemes.length)
          tokens = []
          index = 0
          while index < graphemes.length
            index += 1 while index < graphemes.length && graphemes[index].match?(/\s/)
            break if index >= graphemes.length

            start = index
            quote = nil
            while index < graphemes.length
              char = graphemes[index]
              if quote
                quote = nil if char == quote
              elsif %w[' "].include?(char)
                quote = char
              elsif char.match?(/\s/)
                break
              end
              index += 1
            end
            tokens << { text: graphemes[start...index].join, start: start, finish: index, current: cursor.between?(start, index) }
          end
          tokens << { text: '', start: cursor, finish: cursor, current: true } if tokens.none? { |token| token[:current] }
          tokens
        end

        private_class_method def self.line_replace(opts = {})
          graphemes = opts[:line].scan(/\X/)
          token = opts[:token]
          value = opts[:value].to_s
          graphemes[token[:start]...token[:finish]] = value.scan(/\X/)
          { text: graphemes.join, cursor: token[:start] + value.scan(/\X/).length }
        end

        private_class_method def self.candidates(opts = {})
          tokens = opts[:tokens]
          prefix = opts[:prefix]
          command = tokens.first[:text]
          position = tokens.index { |token| token[:current] }.to_i
          return [filter(values: COMMANDS, prefix: prefix), 'command'] if position.zero?

          case command
          when '/verbose' then [filter(values: %w[on off], prefix: prefix), 'verbosity']
          when '/steer', '/input', '/delegate' then [[], 'free text; no invented values']
          when '/cron' then cron(tokens: tokens, position: position, prefix: prefix)
          when '/memory' then memory(tokens: tokens, position: position, prefix: prefix)
          when '/sessions' then sessions(tokens: tokens, position: position, prefix: prefix)
          when '/skills' then skills(tokens: tokens, position: position, prefix: prefix)
          when '/learning' then learning(tokens: tokens, position: position, prefix: prefix)
          when '/model' then model(tokens: tokens, position: position, prefix: prefix)
          when '/mcp' then mcp(tokens: tokens, position: position, prefix: prefix)
          when '/swarm' then swarm(tokens: tokens, position: position, prefix: prefix, controller: opts[:swarm])
          else [[], 'no further parameters']
          end
        end

        private_class_method def self.filter(opts = {})
          prefix = opts[:prefix].to_s
          Array(opts[:values]).map(&:to_s).uniq.select { |value| prefix.empty? || value.start_with?(prefix) }
        end

        private_class_method def self.cron(opts = {})
          tokens = opts[:tokens]
          position = opts[:position]
          prefix = opts[:prefix]
          return [filter(values: %w[list create run remove], prefix: prefix), 'cron action'] if position == 1
          return [[], 'cron schedule, for example 0 * * * *'] if tokens[1][:text] == 'create' && position == 2
          return [[], 'prompt text'] if tokens[1][:text] == 'create'

          [filter(values: safe { PWN::Cron.list.keys }, prefix: prefix), 'job id']
        end

        private_class_method def self.memory(opts = {})
          tokens = opts[:tokens]
          position = opts[:position]
          prefix = opts[:prefix]
          return [filter(values: %w[list recall remember forget clear], prefix: prefix), 'memory action'] if position == 1
          return [[], 'memory value'] if tokens[1][:text] == 'remember' && position > 2

          [filter(values: safe { PWN::Memory.load.keys }, prefix: prefix), 'memory key']
        end

        private_class_method def self.sessions(opts = {})
          tokens = opts[:tokens]
          position = opts[:position]
          prefix = opts[:prefix]
          return [filter(values: %w[list resume delete stats], prefix: prefix), 'session action'] if position == 1
          return [[], 'no further parameters'] unless %w[resume delete].include?(tokens[1][:text])

          ids = safe { PWN::Sessions.list.map { |row| row[:id] || row['id'] } }
          [filter(values: ids, prefix: prefix), 'session id']
        end

        private_class_method def self.skills(opts = {})
          position = opts[:position]
          prefix = opts[:prefix]
          return [filter(values: %w[list recall], prefix: prefix), 'skills action'] if position == 1

          names = safe { PWN::Skills.keys } if PWN.const_defined?(:Skills)
          [filter(values: names, prefix: prefix), 'skill name']
        end

        private_class_method def self.learning(opts = {})
          tokens = opts[:tokens]
          position = opts[:position]
          prefix = opts[:prefix]
          return [filter(values: %w[list requeue], prefix: prefix), 'learning action'] if position == 1
          return [filter(values: %w[--conflicted conflicted], prefix: prefix), 'list filter'] if tokens[1][:text] == 'list'

          [[], 'no further parameters']
        end

        private_class_method def self.model(opts = {})
          tokens = opts[:tokens]
          position = opts[:position]
          prefix = opts[:prefix]
          engines = safe { REPL.pwn_ai_engines }
          return [filter(values: ['list'] + engines, prefix: prefix), 'engine or list'] if position == 1
          return [filter(values: %w[llms], prefix: prefix), 'remote catalog; not fetched while typing'] if tokens[1][:text] == 'list'
          return [[], 'model id; supported models prompt for effort after Enter (no catalog while typing)'] if position >= 2

          current = safe { [REPL.pwn_ai_engine_model(engine: tokens[1][:text])] }
          [filter(values: current, prefix: prefix), 'configured model']
        end

        private_class_method def self.mcp(opts = {})
          tokens = opts[:tokens]
          position = opts[:position]
          prefix = opts[:prefix]
          actions = %w[list backends use current connect disconnect ping tools call status help]
          backends = safe { PWN::AI::MCP.backends.map { |row| row[:name] } }
          return [filter(values: actions + backends, prefix: prefix), 'mcp action or backend'] if position == 1
          return [filter(values: backends, prefix: prefix), 'backend'] if %w[use connect disconnect].include?(tokens[1][:text])
          return [filter(values: tool_names(backends: backends), prefix: prefix), 'tool name'] if tokens[1][:text] == 'call'

          [[], 'mcp argument']
        end

        private_class_method def self.tool_names(opts = {})
          Array(opts[:backends]).flat_map do |name|
            row = PWN::AI::MCP.backends.find { |backend| backend[:name].to_s == name.to_s }
            Array(row && row[:tools])
          end
        rescue StandardError
          []
        end

        private_class_method def self.swarm(opts = {})
          tokens = opts[:tokens]
          position = opts[:position]
          prefix = opts[:prefix]
          controller = opts[:controller]
          return [filter(values: SWARM, prefix: prefix), 'swarm command'] if position == 1

          context = controller.respond_to?(:completion_context) ? controller.completion_context : {}
          action = tokens[1][:text]
          jobs = Array(context[:jobs]).map { |job| job[:id] || job['id'] }
          agents = Array(context[:agents])
          case action
          when 'status', 'steer', 'cancel' then [filter(values: jobs + (action == 'cancel' ? ['all'] : []), prefix: prefix), 'job id']
          when 'use' then [filter(values: existing_swarms, prefix: prefix), 'swarm id']
          when 'spawn' then [[], position == 2 ? 'persona name' : 'role text']
          when 'retire', 'ask' then [filter(values: agents, prefix: prefix), 'persona']
          when 'debate' then [filter(values: agents, prefix: prefix), 'comma-separated personas, then topic']
          when 'tail' then [[], 'message limit']
          else [[], 'free text']
          end
        end

        private_class_method def self.existing_swarms
          root = PWN::AI::Agent::Swarm::SWARM_ROOT
          return [] unless Dir.exist?(root)

          Dir.children(root)
        rescue StandardError
          []
        end

        private_class_method def self.safe
          Array(yield).map(&:to_s)
        rescue StandardError
          []
        end
      end
    end
  end
end
