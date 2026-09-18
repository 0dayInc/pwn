# frozen_string_literal: true

require 'json'
require 'digest'
require 'json_schemer'
require 'securerandom'
require 'base64'
require 'pwn/ai/agent/tool_guard'
require 'pwn/ai/agent/manifest'

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
          raw  = if fn.key?(:arguments) || fn.key?('arguments')
                   fn[:arguments] || fn['arguments']
                 else
                   '{}'
                 end

          entry = Registry.lookup(name: name) || Registry.lookup(name: repair_name(name: name))
          return JSON.generate(error: "unknown tool: #{name}") unless entry

          args = parse_args(raw: raw, entry: entry)
          args = alias_known_keys(args: args, entry: entry)
          schema = entry.schema[:parameters] || entry.schema['parameters'] || { type: 'object' }
          declaration = Manifest.load(directory: opts[:manifest_directory] || Manifest::DIRECTORY)[entry.name]
          schema = { allOf: [schema, declaration['params']] } if declaration
          if raw.nil?
            required = Array(schema[:required] || schema['required']).map(&:to_s)
            missing = required.reject { |key| ToolGuard.present?(value: args[key.to_sym] || args[key]) }
            return schema_denial(type: 'required', error: "Supply required fields: #{missing.join(', ')}") unless missing.empty?
          end
          type_schema = drop_required(node: schema)
          violation = JSONSchemer.schema(JSON.parse(JSON.generate(type_schema))).validate(JSON.parse(JSON.generate(args))).first
          return schema_denial(violation.transform_keys(&:to_sym)) if violation

          blob = args.inspect
          if defined?(PWN::Plugins::Vault)
            blob = PWN::Plugins::Vault.expand(text: blob)
            args = expand_vault_args(args: args)
          end
          denied = Manifest.check(opts.merge(name: entry.name, args: args))
          return JSON.generate(denied) if denied

          if defined?(Engagement)
            denied = ToolGuard.scope_check!(args: args, command: blob) if defined?(ToolGuard) && ToolGuard.respond_to?(:scope_check!)
            denied ||= Engagement.deny_if_out_of_scope(args: args, command: blob)
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
          if blob.match?(/open_sockraw|sockraw/) && defined?(PWN::Plugins::PreflightChecker) &&
             PWN::Plugins::PreflightChecker.respond_to?(:cap_net_raw?) && !PWN::Plugins::PreflightChecker.cap_net_raw?
            return JSON.generate(
              success: false,
              error: 'capability missing CAP_NET_RAW',
              substitute: 'PWN::Plugins::Packet.tcp_connect_scan',
              code: 'CAP_DENY'
            )
          end
          ack = Confirmation.gate(
            name: entry.name,
            args: args,
            engagement_id: opts[:engagement_id] || args[:engagement_id] || args['engagement_id'],
            operator_ack: opts[:operator_ack] || args[:operator_ack] || args['operator_ack'],
            scope_path: opts[:scope_path]
          )
          return JSON.generate(ack) if ack

          budget = prepare_budget(opts.merge(entry: entry, args: args))
          return JSON.generate(budget[:denial]) if budget && budget[:denial]

          started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          begin
            result = entry.handler.call(args)
          rescue StandardError => e
            finish_budget(budget: budget, result: { error: e.is_a?(Timeout::Error) ? 'timeout' : e.class.name }, elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
            raise
          end
          telemetry = finish_budget(budget: budget, result: result, elapsed: Process.clock_gettime(Process::CLOCK_MONOTONIC) - started)
          result = Result.page(value: result, entry: entry, session_id: opts[:session_id])
          result = ToolGuard.quarantine_output(text: result) if defined?(ToolGuard) && result.is_a?(String) && ToolGuard.respond_to?(:quarantine_output)
          note_taint(text: result)
          if defined?(PWN::Plugins::Vault) && result.is_a?(String)
            result = PWN::Plugins::Vault.redact(text: result)
          elsif defined?(PWN::Plugins::Vault) && result.is_a?(Hash)
            result = JSON.parse(PWN::Plugins::Vault.redact(text: JSON.generate(result)))
          end
          response = { success: true, result: result, effect: effect(name: entry.name, args: args) }
          response[:budget] = telemetry if telemetry
          if telemetry && telemetry[:remaining_s].zero?
            response[:success] = false
            response[:error] = 'budget_exhausted'
          end
          JSON.generate(response)
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

        private_class_method def self.schema_denial(opts = {})
          pointer = opts[:data_pointer].to_s
          message = opts[:error].to_s
          data = opts[:data]
          # Schema failures identify a JSON field, not a span of command bytes.
          # Do not echo whole argument objects (which may contain credentials).
          token = data.to_s unless data.nil? || data.is_a?(Hash) || data.is_a?(Array)
          denial = ToolGuard.invalid_payload(
            code: 'SCHEMA_DENY', rule_id: "schema.#{opts[:type]}",
            match: token, hint: message,
            remedy: "Correct #{pointer.empty? ? 'the tool arguments' : pointer}: #{message}. Resubmit arguments matching the advertised JSON schema."
          )
          JSON.generate(denial.merge(success: false, data_pointer: pointer))
        end

        # Caller owns task lifecycle. Fallback is thread-local, never process-global.
        private_class_method def self.prepare_budget(opts = {})
          entry = opts[:entry]
          args = opts[:args]
          if entry.name == 'shell' && (args[:background] == true || (!args.key?(:timeout) && ToolGuard.auto_job?(payload: args[:command].to_s)))
            args[:background] = true
            return nil
          end
          schema = JSON.parse(JSON.generate(entry.schema))
          return nil unless schema.dig('parameters', 'properties', 'timeout')

          ledger = opts[:budget_ledger] || (Thread.current[:pwn_dispatch_budget] ||= {})
          chains = ledger[:chains] ||= {}
          key = opts[:budget_key] || entry.name
          chain = chains[key] ||= { payloads: {} }
          payload = args.reject { |name, _| name.to_s == 'timeout' }
          hash = Digest::SHA256.hexdigest(JSON.generate(canonical(value: payload)))
          active = chain[:active]
          return { denial: { success: false, error: 'retry_required', payload_hash: active, hint: 'Retry the identical payload; its timeout will increase automatically.' } } if active && active != hash && (10_800 - chain[:payloads][active][:spent_s]).floor >= 1

          record = chain[:payloads][hash] ||= { spent_s: 0.0, timed_out: false }
          return { denial: { success: false, error: 'budget_exhausted', payload_hash: hash, mutations: ledger[:mutations].to_i, hint: 'Pivot to a different tool or report this blocked approach; other task work remains available.' } } if (10_800 - record[:spent_s]).floor < 1 || (active && active != hash && ledger[:mutations].to_i >= 10)

          ledger[:mutations] = ledger[:mutations].to_i + 1 if active && active != hash
          timeout = if record[:timed_out]
                      record[:timeout_s] + 180
                    else
                      ToolGuard.deadline_s(timeout: args[:timeout], kind: entry.name == 'shell' ? :shell : :ruby, payload: JSON.generate(payload))
                    end
          timeout = [timeout, (10_800 - record[:spent_s]).floor].min
          args[:timeout] = timeout
          { ledger: ledger, chain: chain, record: record, hash: hash, timeout: timeout }
        end

        private_class_method def self.canonical(opts = {})
          value = opts[:value]
          case value
          when Hash then value.keys.sort_by(&:to_s).to_h { |key| [key.to_s, canonical(value: value[key])] }
          when Array then value.map { |item| canonical(value: item) }
          else value
          end
        end

        private_class_method def self.finish_budget(opts = {})
          budget = opts[:budget]
          return nil unless budget

          result = opts[:result]
          timed_out = result.is_a?(Hash) && (result[:error] || result['error']).to_s.match?(/\Atimeout(?:\b|:)/i)
          record = budget[:record]
          record[:spent_s] += timed_out ? budget[:timeout] : opts[:elapsed]
          record[:timeout_s] = budget[:timeout]
          record[:timed_out] = timed_out
          budget[:chain][:active] = timed_out ? budget[:hash] : nil
          remaining = [10_800 - record[:spent_s], 0].max
          if timed_out
            result.delete('next_timeout')
            result.delete('mutations')
            result.delete('scenario')
            result.delete('hint')
            result[:next_timeout] = [record[:timeout_s] + 180, remaining.floor].min
            result[:mutations] = budget[:ledger][:mutations].to_i
            result[:scenario] = remaining.floor.zero? ? 'budget_exhausted' : 'deadline'
            result[:hint] = remaining.floor.zero? ? 'Payload budget exhausted; mutate this approach or pivot to another tool.' : 'Retry the identical payload; Dispatch increases timeout by 180 seconds.'
          end
          { payload_hash: budget[:hash], timeout_s: record[:timeout_s], spent_s: record[:spent_s], remaining_s: remaining, mutations: budget[:ledger][:mutations].to_i }
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

        private_class_method def self.alias_known_keys(opts = {})
          args = opts[:args]
          return args unless args.is_a?(Hash)

          schema = opts[:entry]&.schema || {}
          params = schema[:parameters] || schema['parameters'] || {}
          required = Array(params[:required] || params['required']).map(&:to_s)
          return args if required.empty? || !defined?(ToolGuard)

          coerced = ToolGuard.coerce_args(args: args, required: required)
          coerced.delete(:__schema_error)
          coerced.delete(:__schema_hint)
          coerced
        end

        private_class_method def self.drop_required(opts = {})
          node = opts[:node]
          case node
          when Hash
            node.each_with_object({}) do |(key, value), acc|
              next if key.to_s == 'required'

              acc[key] = drop_required(node: value)
            end
          when Array
            node.map { |value| drop_required(node: value) }
          else
            node
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
          return :write if blob.match?(WRITE_ARGV_RX)
          return :browse if blob.match?(BROWSE_ARGV_RX)
          return :eval if name == 'pwn_eval'

          :read
        rescue StandardError
          :read
        end

        private_class_method def self.argv_blob(opts = {})
          args = opts[:args]
          args = JSON.parse(args, symbolize_names: true) if args.is_a?(String) && args.strip.start_with?('{')
          case args
          when Hash
            return Base64.strict_decode64((args[:data] || args['data']).to_s) if (args[:encoding] || args['encoding']).to_s == 'base64'

            args.values.join(' ')
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
          grams = text.scan(/.{24,}/).first(20)
          store = Thread.current[:pwn_taint] ||= []
          grams.each { |g| store << g[0, 64] }
          store.shift while store.length > 200
          store
        end

        private_class_method def self.taint_blocked?(opts = {})
          mode = taint_mode
          return false if mode == 'off'

          blob = opts[:args].inspect
          return false if blob.length < 24
          return false if opts[:args].is_a?(Hash) && (opts[:args][:taint_ack] == true || opts[:args]['taint_ack'] == true)

          hit = Array(Thread.current[:pwn_taint]).any? { |g| g.length >= 24 && blob.include?(g) }
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
              tool_call: 'required - Hash { id:, type:, function: { name:, arguments: } }',
              manifest_directory: 'optional - trusted manifest YAML directory',
              budget_ledger: 'optional - caller-owned Hash retained across one task',
              budget_key: 'optional - trusted approach identifier; defaults to tool name',
              scope_policy: 'optional - trusted policy Hash',
              scope_path: 'optional - trusted scope file path',
              session_id: 'optional - session directory for oversized result artifacts',
              audit_path: 'optional - trusted audit JSONL path',
              approval_callback: 'optional - trusted callback for prompt risk gates',
              engagement_id: 'optional - engagement id used to cache exploit/destructive ACK',
              operator_ack: 'optional - true records a one-time ACK for this engagement'
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
