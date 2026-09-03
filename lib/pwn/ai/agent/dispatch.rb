# frozen_string_literal: true

require 'json'
require 'securerandom'
require 'pwn/ai/agent/tool_guard'

module PWN
  module AI
    module Agent
      # Tool-call dispatch: takes a single tool_call object (OpenAI shape),
      # looks up the registered handler, parses args, runs it, and returns a
      # JSON string suitable for a role:'tool' message.
      #
      # TOLERANT DISPATCH (local-model scaffolding)
      # -------------------------------------------
      # Local models running on Ollama frequently emit almost-
      # right tool calls: `run_shell` instead of `shell`, trailing commas,
      # single-quoted JSON, arguments as a bare string. Strict parsing burns
      # an iteration and often spirals. Dispatch now:
      #   * repair_name  — Levenshtein-matches unknown names to the closest
      #                    registered tool and records a Mistakes fingerprint
      #                    (source: :repair) so the KNOWN MISTAKES block
      #                    eventually teaches the model the right name.
      #   * parse_args   — falls back to a JSON5-ish clean-up pass (strip
      #                    trailing commas, swap single→double quotes, wrap a
      #                    bare scalar as the tool's sole required arg).
      # Frontier engines never hit these paths — repair is a no-op when the
      # name/JSON are already valid.
      module Dispatch
        # Supported Method Parameters::
        # json_str = PWN::AI::Agent::Dispatch.call(
        #   tool_call: 'required - Hash { id:, type:, function: { name:, arguments: } }'
        # )

        public_class_method def self.call(opts = {})
          tool_call = opts[:tool_call]
          raise 'ERROR: tool_call is required' if tool_call.nil?

          fn   = tool_call[:function] || tool_call['function'] || {}
          name = (fn[:name] || fn['name']).to_s
          raw  = fn[:arguments] || fn['arguments'] || '{}'

          entry = Registry.lookup(name: name) || Registry.lookup(name: repair_name(name: name))
          return JSON.generate(error: "unknown tool: #{name}") unless entry

          args = parse_args(raw: raw, entry: entry)
          required = Array(entry.schema&.dig(:parameters, :required))
          args = ToolGuard.coerce_args(args: args, required: required) if defined?(ToolGuard)
          blob = args.inspect
          if defined?(PWN::Plugins::Vault)
            blob = PWN::Plugins::Vault.expand(text: blob)
            args = expand_vault_args(args: args)
          end
          if defined?(Engagement)
            denied = Engagement.deny_if_out_of_scope(args: args, command: blob)
            return JSON.generate(denied) if denied
          end
          if defined?(ToolGuard) && ToolGuard.respond_to?(:policy_decision)
            pol = ToolGuard.policy_decision(name: entry.name, args: args)
            return JSON.generate(pol) if pol.is_a?(Hash) && pol[:action] == 'deny'
          end
          return JSON.generate(success: false, error: 'taint: tool-output instruction in args', code: 'TAINT_DENY') if taint_blocked?(name: entry.name, args: args)
          if defined?(ToolGuard) && ToolGuard.respond_to?(:canary_leak?) &&
             ToolGuard.canary_leak?(text: args.inspect)
            return JSON.generate(success: false, error: 'refused: session canary in outbound args', code: 'CANARY_DENY', rule_id: 'canary')
          end
          if defined?(ToolGuard) && ToolGuard.respond_to?(:refuse_copied_persist?) &&
             ToolGuard.refuse_copied_persist?(name: entry.name, args: args)
            return JSON.generate(
              success: false,
              error: 'refused: memory_remember/skills_update text copied from last tool output'
            )
          end
          result = entry.handler.call(args)
          result = ToolGuard.quarantine_output(text: result) if defined?(ToolGuard) && result.is_a?(String) && ToolGuard.respond_to?(:quarantine_output)
          note_taint(text: result)
          if defined?(PWN::Plugins::Vault) && result.is_a?(String)
            result = PWN::Plugins::Vault.redact(text: result)
          elsif defined?(PWN::Plugins::Vault) && result.is_a?(Hash)
            result = JSON.parse(PWN::Plugins::Vault.redact(text: JSON.generate(result)))
          end
          JSON.generate(success: true, result: result, effect: effect(name: entry.name, args: args))
        rescue StandardError => e
          JSON.generate(
            success: false,
            error: "#{e.class}: #{e.message}",
            backtrace: Array(e.backtrace).first(3)
          )
        end

        # Supported Method Parameters::
        # fixed = PWN::AI::Agent::Dispatch.repair_name(
        #   name: 'required - possibly-wrong tool name emitted by the model'
        # )
        #
        # Returns the closest registered tool name by Levenshtein distance
        # (max distance = 1/3 of the emitted name, min 3) or nil when nothing
        # is close enough. Every successful repair is fingerprinted into
        # Mistakes so the negative-feedback loop trains the model's output
        # format via its own system prompt.

        public_class_method def self.repair_name(opts = {})
          name = opts[:name].to_s
          return nil if name.empty?

          pool = Registry.all.map(&:name)
          return nil if pool.empty?

          best, dist = pool.map { |n| [n, DidYouMean::Levenshtein.distance(n, name)] }
                           .min_by(&:last)
          thresh = [(name.length / 3.0).ceil, 3].max
          return nil if dist > thresh

          if defined?(Mistakes)
            Mistakes.record(
              tool: 'tool_name',
              error: "model emitted '#{name}', repaired to '#{best}'",
              args: name,
              source: :repair
            )
          end
          best
        rescue StandardError
          nil
        end

        private_class_method def self.parse_args(opts = {})
          raw   = opts[:raw]
          entry = opts[:entry]
          case raw
          when Hash   then symbolize(hash: raw)
          when String then parse_string_args(raw: raw, entry: entry)
          when nil    then {}
          else symbolize(hash: raw.to_h)
          end
        end

        private_class_method def self.parse_string_args(opts = {})
          raw   = opts[:raw].to_s
          entry = opts[:entry]
          return {} if raw.strip.empty?

          JSON.parse(raw, symbolize_names: true)
        rescue JSON::ParserError => e
          # Tolerant retry: strip trailing commas, normalise single quotes,
          # coerce a bare scalar into the tool's sole required parameter.
          cleaned = raw.gsub(/,(\s*[}\]])/, '\1').tr("'", '"')
          begin
            return JSON.parse(cleaned, symbolize_names: true)
          rescue JSON::ParserError
            req = Array(entry&.schema&.dig(:parameters, :required))
            return { req.first.to_sym => raw.strip.gsub(/\A["']|["']\z/, '') } if req.length == 1 && !raw.strip.start_with?('{', '[')
          end
          raise ArgumentError, "invalid JSON arguments: #{e.message}"
        end

        # Supported Method Parameters::
        # calls = PWN::AI::Agent::Dispatch.tool_calls_from_text(
        #   text: 'required - assistant plain-text that may embed shell(...) / JSON tool forms'
        # )
        #
        # Local / abliterated models often print tool invocations as content
        # instead of native message.tool_calls. Supported shapes include:
        #   shell(command="id") / shell({"command":"id"}) / shell("id")
        #   {"name":"shell","arguments":{...}} / {"function":{"name":...}}
        #   {"tool":"shell","arguments":{...}} / {"call":"shell","arguments":{...}}
        #   call:shell{command: "uname -s"} / tool:shell{"command":"id"}
        # When structured tool_calls are empty, Loop coerces those strings into
        # OpenAI-shaped tool_call hashes so Dispatch runs them instead of
        # treating the string as a FINAL answer.

        public_class_method def self.tool_calls_from_text(opts = {})
          text = opts[:text].to_s
          return [] if text.strip.empty?

          Registry.discover if defined?(Registry) && Registry.respond_to?(:discover)
          known = if defined?(Registry)
                    Registry.all.map { |e| e.name.to_s }.reject(&:empty?)
                  else
                    %w[shell pwn_eval]
                  end
          return [] if known.empty?

          names_alt = known.map { |n| Regexp.escape(n) }.join('|')
          calls = []
          seen = {}

          add = lambda do |name, args|
            name = name.to_s
            next unless known.include?(name)

            args_h = case args
                     when Hash then symbolize(hash: args)
                     when String
                       s = args.strip
                       begin
                         parsed = JSON.parse(s, symbolize_names: true)
                         parsed.is_a?(Hash) ? parsed : { value: parsed }
                       rescue JSON::ParserError
                         h = {}
                         s.scan(/([A-Za-z_]\w*)\s*[:=]\s*(?:"((?:\\.|[^"])*)"|'((?:\\.|[^'])*)'|([^\s,)}{]+))/) do
                           k = Regexp.last_match(1)
                           h[k.to_sym] = Regexp.last_match(2) || Regexp.last_match(3) || Regexp.last_match(4)
                         end
                         if h.empty?
                           entry = (Registry.lookup(name: name) if defined?(Registry))
                           req = Array(entry&.schema&.dig(:parameters, :required))
                           h = req.length == 1 ? { req.first.to_sym => s } : { command: s }
                         end
                         h
                       end
                     else
                       {}
                     end
            key = "#{name}|#{JSON.generate(args_h)}"
            next if seen[key]

            seen[key] = true
            calls << {
              id: "textcall_#{calls.length + 1}_#{SecureRandom.hex(3)}",
              type: 'function',
              function: {
                name: name,
                # OpenAI/xAI wire format requires a JSON string, not a map.
                arguments: JSON.generate(args_h)
              }
            }
          end

          # Balanced-delimiter extractor used for name(...) and call:name{...}.
          extract_balanced = lambda do |open_ch, close_ch, from|
            depth = 1
            i = from
            in_s = nil
            esc = false
            while i < text.length && depth.positive?
              ch = text[i]
              if in_s
                if esc
                  esc = false
                elsif ch == '\\'
                  esc = true
                elsif ch == in_s
                  in_s = nil
                end
              elsif ['"', "'"].include?(ch)
                in_s = ch
              elsif ch == open_ch
                depth += 1
              elsif ch == close_ch
                depth -= 1
              end
              i += 1
            end
            depth.zero? ? [text[from...(i - 1)].to_s.strip, i] : nil
          end

          # JSON object forms:
          #   {"name":"shell","arguments":{...}}
          #   {"function":{"name":"shell","arguments":{...}}}
          #   {"tool":"shell","arguments":{...}} / {"call":"shell",...}
          #   {"type":"call","name":"shell",...}
          text.scan(/\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}/m).each do |blob|
            begin
              j = JSON.parse(blob, symbolize_names: true)
            rescue JSON::ParserError
              next
            end
            next unless j.is_a?(Hash)

            name = (
              j[:name] || j[:tool] || j[:call] ||
              j.dig(:function, :name) || j.dig(:tool_call, :name)
            ).to_s
            # Skip pure type tags mistaken as names (e.g. {"call":{...}} trees).
            next if name.empty? || %w[function tool_call].include?(name)

            args = j[:arguments] || j[:args] || j[:parameters] ||
                   j.dig(:function, :arguments) || j.dig(:tool_call, :arguments) || {}
            add.call(name, args)
          end

          # Colon-brace forms (OpenWebUI / abliterated dumps):
          #   call:shell{command: "uname -s"}
          #   tool:shell{"command":"id"}
          #   call:shell{command="id"}
          rx_colon = /\b(?:call|tool)\s*:\s*(#{names_alt})\s*\{/i
          idx = 0
          while (m = text.match(rx_colon, idx))
            name = m[1]
            extracted = extract_balanced.call('{', '}', m.end(0))
            if extracted
              # Re-wrap: balanced extractor yields the interior only. Paren form
              # shell({...}) keeps braces inside (...); brace form must restore
              # them so JSON.parse / kwarg scan see a full object body.
              add.call(name, "{#{extracted[0]}}")
            end
            idx = m.begin(0) + 1
          end

          # Call forms: shell(command="...") / shell({"command":"id"}) / shell("id")
          rx = /\b(#{names_alt})\s*\(/i
          idx = 0
          while (m = text.match(rx, idx))
            name = m[1]
            extracted = extract_balanced.call('(', ')', m.end(0))
            add.call(name, extracted[0]) if extracted
            idx = m.begin(0) + 1
          end

          calls
        rescue StandardError
          []
        end

        # Effect of a tool call from NAME + ARGV only — never stdout.
        # :write mutate, :browse navigate, :recall store lookup, :read/:eval observe.
        WRITE_ARGV_RX = /
          \bsed\s+-i\b|\bruby\s+-i\b|\btee\b|
          (?:\s|\A)>{1,2}\s+\S|
          File\.(?:write|open|binwrite)|IO\.write|
          \bopen\s*\([^)]*['"]w|
          \b(?:cp|mv|rm|mkdir|touch|chmod|chown)\b|
          \bgit\s+(?:add|commit|rm)
        /ix
        BROWSE_ARGV_RX = /
          TransparentBrowser|browser_obj|\.goto\b|dump_links|
          watir|headless_?chrome|\bdevtools\b
        /ix
        RECALL_TOOLS = %w[
          memory_recall session_recall skills_recall sessions_view
          sessions_list sessions_current
        ].freeze
        STORE_TOOLS = %w[
          memory_remember mistakes_record mistakes_resolve
          learning_note_outcome skill_create skill_add_reference skills_update
        ].freeze

        public_class_method def self.effect(opts = {})
          name = opts[:name].to_s
          return :read if name.empty?
          return :recall if RECALL_TOOLS.include?(name)
          return :store if STORE_TOOLS.include?(name)

          blob = argv_blob(args: opts[:args])
          return :browse if blob.match?(BROWSE_ARGV_RX)
          return :write if blob.match?(WRITE_ARGV_RX)
          return :eval if name == 'pwn_eval'

          :read
        rescue StandardError
          :read
        end

        private_class_method def self.argv_blob(opts = {})
          args = opts[:args]
          args = JSON.parse(args, symbolize_names: true) if args.is_a?(String) && args.strip.start_with?('{')
          case args
          when Hash then args.values.join(' ')
          else args.to_s
          end
        rescue StandardError
          opts[:args].to_s
        end

        private_class_method def self.symbolize(opts = {})
          hash = opts[:hash] ||= {}
          hash.each_with_object({}) { |(k, v), m| m[k.to_sym] = v }
        end

        private_class_method def self.expand_vault_args(opts = {})
          args = opts[:args]
          return args unless args.is_a?(Hash)

          args.transform_values do |v|
            v.is_a?(String) ? PWN::Plugins::Vault.expand(text: v) : v
          end
        rescue StandardError
          opts[:args]
        end

        private_class_method def self.note_taint(opts = {})
          text = opts[:text].to_s
          grams = text.scan(/.{12,}/).first(20)
          store = Thread.current[:pwn_taint] ||= []
          grams.each { |g| store << g[0, 64] }
          store.shift while store.length > 200
          store
        end

        private_class_method def self.taint_blocked?(opts = {})
          mode = taint_mode
          return false if mode == 'off'

          blob = opts[:args].inspect
          return false if blob.length < 12
          return false if opts[:args].is_a?(Hash) && (opts[:args][:taint_ack] == true || opts[:args]['taint_ack'] == true)

          hit = Array(Thread.current[:pwn_taint]).any? { |g| g.length >= 12 && blob.include?(g) }
          return false unless hit
          return false unless blob.match?(/curl |bash -c|sh -c|\|\s*sh\b/i)

          mode == 'enforce'
        rescue StandardError
          false
        end

        private_class_method def self.taint_mode(opts = {})
          override = opts[:mode]
          return override.to_s unless override.to_s.empty?
          return 'enforce' unless defined?(PWN::Env)

          (PWN::Env.dig(:ai, :taint, :mode) || 'enforce').to_s
        rescue StandardError
          'enforce'
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Run call and return its result
            #{self}.call(
              tool_call: 'required - Hash { id:, type:, function: { name:, arguments: } }'
            )

            # Run repair name and return its result
            #{self}.repair_name(
              name: 'required - possibly-wrong tool name emitted by the model'
            )

            # Run tool calls from text and return its result
            #{self}.tool_calls_from_text(
              text: 'required - assistant plain-text that may embed shell(...) / JSON tool forms',
              call: 'optional - shell{command: uname -s} / tool:shell{command:id}'
            )

            # Run effect and return its result
            #{self}.effect(
              name: 'required - binary or identifier name',
              args: 'optional - args value consumed by #effect'
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
