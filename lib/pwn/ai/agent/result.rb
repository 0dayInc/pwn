# frozen_string_literal: true

require 'json'
require 'base64'

module PWN
  module AI
    module Agent
      # Conditioning applied to every tool result before it re-enters the
      # conversation as a role:'tool' message: lossless paging + credential
      # redaction. Keeps the context window bounded and avoids leaking
      # PWN::Env credentials back into the model.
      module Result
        DEFAULT_MAX       = 24_000
        LOCAL_DEFAULT_MAX = 4_000

        # Generic high-confidence credential shapes scrubbed from tool
        # output regardless of PWN::Env contents. Built via concatenation
        # so nothing token-shaped appears as a literal in this source file.
        REDACT_PATTERNS = [
          Regexp.new(%w[s k - [A-Za-z0-9]{20,}].join),                        # OpenAI-style
          Regexp.new(%w[x o x [baprs]-[A-Za-z0-9-]{10,}].join),               # Slack
          Regexp.new(%w[g h [pousr]_[A-Za-z0-9]{36,}].join),                  # GitHub PAT
          Regexp.new(%w[A K I A [0-9A-Z]{16}].join),                          # AWS access key id
          Regexp.new(%w[A I z a [A-Za-z0-9_-]{35}].join),                     # Google API key
          Regexp.new(
            '-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----',
            Regexp::MULTILINE
          )
        ].freeze

        SENSITIVE_KEYS = %i[api_key key pass password psk token secret bearer].freeze

        # Supported Method Parameters::
        # safe = PWN::AI::Agent::Result.condition(
        #   content: 'required - String returned by Dispatch.call',
        #   entry: 'optional - Registry::Entry (used for max_chars; nil → DEFAULT_MAX)'
        # )

        public_class_method def self.condition(opts = {})
          content = opts[:content].to_s
          content = JSON.generate(spill_summary(content: content, session_id: opts[:session_id])) if content.bytesize > token_limit(entry: opts[:entry]) || !content.dup.force_encoding('UTF-8').valid_encoding?
          redact(content: content)
        end

        # Preserve the original handler result before redaction/quarantine.
        public_class_method def self.page(opts = {})
          value = opts[:value]
          safe_value = value.is_a?(String) ? value : transport_value(value: value)
          content = value.is_a?(String) ? value : JSON.generate(safe_value)
          return safe_value if content.bytesize <= token_limit(entry: opts[:entry]) && content.dup.force_encoding('UTF-8').valid_encoding?

          summary = spill_summary(content: content, session_id: opts[:session_id])
          summary[:serialization] = value.is_a?(String) ? 'raw' : 'json (binary strings use encoding/base64 wrappers)'
          if value.is_a?(Hash)
            %w[success ok exit exit_code exit_status timed_out error code].each do |key|
              next unless value.key?(key.to_sym) || value.key?(key)

              field = value.key?(key.to_sym) ? value[key.to_sym] : value[key]
              summary[key.to_sym] = field if [true, false, nil].include?(field) || field.is_a?(Numeric) || (field.is_a?(String) && field.bytesize <= 128)
            end
          end
          summary
        end

        # A byte is a conservative token upper bound; never assume four bytes
        # per token for arbitrary strings/hex/binary dumps. No tokenizer needed.
        public_class_method def self.token_limit(opts = {})
          configured = PWN::Env.dig(:ai, :agent, :artifact_max_tokens).to_i if defined?(PWN::Env)
          limit = configured.to_i.positive? ? configured : default_max / 4
          cap = opts[:entry]&.max_chars.to_i
          limit = [limit, cap].min if cap.positive?
          [limit, 1024].max
        end

        # Reserve room for JSON escaping, metadata, and the dispatch envelope.
        public_class_method def self.page_length
          ((token_limit - 768) / 8).clamp(32, 2048)
        end

        private_class_method def self.spill_summary(opts = {})
          content = opts[:content]
          artifact = PWN::Plugins::ArtifactRegistry.spill(bytes: content, session_id: opts[:session_id] || Thread.current[:pwn_session_id] || 'default')
          {
            artifact: artifact,
            summary: 'Full result saved without truncation. Use artifact_read(handle, offset, length) or artifact_grep(handle, regex); offsets are bytes.',
            preview: redact(content: content.byteslice(0, 32).to_s.dup.force_encoding('UTF-8').scrub)
          }
        end

        private_class_method def self.transport_value(opts = {})
          value = opts[:value]
          case value
          when Hash then value.transform_values { |v| transport_value(value: v) }
          when Array then value.map { |v| transport_value(value: v) }
          when String
            value.dup.force_encoding('UTF-8').valid_encoding? ? value.dup.force_encoding('UTF-8') : { encoding: 'base64', body: Base64.strict_encode64(value) }
          else value
          end
        end

        # Engine-aware default: ollama keeps history inside a tight num_ctx;
        # a 24k tool dump on every call eats the window before useful work.
        # Override via PWN::Env[:ai][:ollama][:result_max].
        public_class_method def self.default_max
          eng = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s.downcase.to_sym
          if %i[ollama openwebui].include?(eng)
            v = (PWN::Env.dig(:ai, eng, :result_max) if defined?(PWN::Env))
            return v.to_i if v.to_i.positive?

            return LOCAL_DEFAULT_MAX
          end
          DEFAULT_MAX
        rescue StandardError
          DEFAULT_MAX
        end

        # Supported Method Parameters::
        # safe = PWN::AI::Agent::Result.redact(
        #   content: 'required - String to scrub of credential-shaped substrings'
        # )

        public_class_method def self.redact(opts = {})
          out = opts[:content].to_s.dup
          env_credential_values.each do |val|
            next if val.to_s.length < 6

            out = out.gsub(val.to_s, '<<<REDACTED>>>')
          end
          REDACT_PATTERNS.each { |re| out = out.gsub(re, '<<<REDACTED>>>') }
          out
        end

        private_class_method def self.env_credential_values
          return [] unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          collect(hash: PWN::Env)
        rescue StandardError
          []
        end

        private_class_method def self.collect(opts = {})
          hash = opts[:hash] ||= {}
          acc  = opts[:acc]  ||= []
          hash.each do |k, v|
            if v.is_a?(Hash)
              collect(hash: v, acc: acc)
            elsif SENSITIVE_KEYS.include?(k.to_s.downcase.to_sym) && v.is_a?(String) && !v.empty?
              acc << v
            end
          end
          acc
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Run condition and return its result
            #{self}.condition(
              content: 'required - String returned by Dispatch.call',
              entry: 'optional - Registry::Entry (used for max_chars; nil → DEFAULT_MAX)',
              session_id: 'optional - session directory used for lossless spilled results'
            )

            # Preserve oversized handler results before redaction or quarantine.
            #{self}.page(
              value: 'required - original tool handler result to condition',
              entry: 'optional - registry entry with an inline size cap',
              session_id: 'optional - session directory for the saved result'
            )

            # Conservative byte-based token bound, configurable through ai.agent.artifact_max_tokens.
            #{self}.token_limit(entry: 'optional - registry entry imposing a smaller cap')

            # Maximum page bytes with space reserved for response metadata.
            #{self}.page_length

            # Engine-aware default: ollama keeps history inside a tight num_ctx;
            #{self}.default_max

            # Run redact and return its result
            #{self}.redact(
              content: 'required - String to scrub of credential-shaped substrings'
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
