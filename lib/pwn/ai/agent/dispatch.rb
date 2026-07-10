# frozen_string_literal: true

require 'json'

module PWN
  module AI
    module Agent
      # Tool-call dispatch: takes a single tool_call object (OpenAI shape),
      # looks up the registered handler, parses args, runs it, and returns a
      # JSON string suitable for a role:'tool' message.
      #
      # TOLERANT DISPATCH (local-model scaffolding)
      # -------------------------------------------
      # Local models (qwen/llama/mistral on Ollama) frequently emit almost-
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
          result = entry.handler.call(args)
          JSON.generate(success: true, result: result)
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

        private_class_method def self.symbolize(opts = {})
          hash = opts[:hash] ||= {}
          hash.each_with_object({}) { |(k, v), m| m[k.to_sym] = v }
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              json_str = PWN::AI::Agent::Dispatch.call(
                tool_call: {
                  id: 'call_1',
                  type: 'function',
                  function: { name: 'shell', arguments: '{"command":"id"}' }
                }
              )

              PWN::AI::Agent::Dispatch.repair_name(name: 'run_shell')  # => 'shell'

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
