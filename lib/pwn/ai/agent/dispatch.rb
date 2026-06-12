# frozen_string_literal: true

require 'json'

module PWN
  module AI
    module Agent
      # Tool-call dispatch: takes a single tool_call object (OpenAI shape),
      # looks up the registered handler, parses args, runs it, and returns a
      # JSON string suitable for a role:'tool' message.
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

          entry = Registry.lookup(name: name)
          return JSON.generate(error: "unknown tool: #{name}") unless entry

          args = parse_args(raw: raw)
          result = entry.handler.call(args)
          JSON.generate(success: true, result: result)
        rescue StandardError => e
          JSON.generate(
            success: false,
            error: "#{e.class}: #{e.message}",
            backtrace: Array(e.backtrace).first(3)
          )
        end

        private_class_method def self.parse_args(opts = {})
          raw = opts[:raw]
          case raw
          when Hash   then symbolize(hash: raw)
          when String then raw.strip.empty? ? {} : JSON.parse(raw, symbolize_names: true)
          when nil    then {}
          else symbolize(hash: raw.to_h)
          end
        rescue JSON::ParserError => e
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

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
