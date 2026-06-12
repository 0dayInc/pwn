# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # Conditioning applied to every tool result before it re-enters the
      # conversation as a role:'tool' message: hard size cap + credential
      # redaction. Keeps the context window bounded and avoids leaking
      # PWN::Env credentials back into the model.
      module Result
        DEFAULT_MAX = 24_000

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
          entry   = opts[:entry]
          cap     = entry ? entry.max_chars : DEFAULT_MAX

          content = "#{content[0, cap]}…[truncated #{opts[:content].to_s.length - cap} chars]" if content.length > cap
          redact(content: content)
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
          puts <<~USAGE
            USAGE:
              safe = PWN::AI::Agent::Result.condition(
                content: json_string,
                entry: PWN::AI::Agent::Registry.lookup(name: 'shell')
              )
              safe = PWN::AI::Agent::Result.redact(content: string)

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
