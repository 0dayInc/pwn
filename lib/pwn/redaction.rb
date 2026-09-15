# frozen_string_literal: true

require 'digest'

module PWN
  # Shared write-boundary redaction. Never opens a credential store.
  module Redaction
    PATTERNS = {
      pem: /-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)/m,
      authorization: /\b(?:Proxy-)?Authorization\s*[:=]\s*(?!\[REDACTED:)[^\r\n"'\\]+/i,
      jwt: /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
      aws: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
      bearer: %r{\bBearer\s+[A-Za-z0-9._~+/=-]+}i,
      api_key: /\b(?:sk|rk|xai|xox[baprs]|ghp|gho|ghu|ghs|ghr|glpat)[-_][A-Za-z0-9_-]{16,}/,
      password: /\b(?:password|passwd|api[_-]?key|access[_-]?token|refresh[_-]?token|secret)\s*[:=]\s*(?!\[REDACTED:)[^\s,"'}]+/i,
      cookie: /\bSet-Cookie:\s*(?!\[REDACTED:)[^\r\n]+/i
    }.freeze
    SECRET_FIELD = /\A(?:password|passwd|secret|api[_-]?key|authorization|proxy-authorization|access[_-]?token|refresh[_-]?token|private[_-]?key|client[_-]?secret)\z/i

    public_class_method def self.redact(opts = {})
      value = opts[:value]
      case value
      when Hash
        value.to_h do |key, item|
          clean = if key.to_s.match?(SECRET_FIELD) && !item.nil?
                    token(kind: key.to_s.downcase, value: item.to_s)
                  else
                    redact(value: item)
                  end
          [key.is_a?(String) ? redact(value: key) : key, clean]
        end
      when Array then value.map { |item| redact(value: item) }
      when String
        PATTERNS.reduce(value.dup) do |text, (kind, regex)|
          text.split(/(\[REDACTED:[^:\]]+:[0-9a-f]{8}\])/).map do |part|
            part.start_with?('[REDACTED:') ? part : part.gsub(regex) { |match| token(kind: kind, value: match) }
          end.join
        end
      else value
      end
    end

    public_class_method def self.token(opts = {})
      value = opts[:value].to_s
      return value if value.match?(/\A\[REDACTED:[^:]+:[0-9a-f]{8}\]\z/)

      "[REDACTED:#{opts[:kind]}:#{Digest::SHA256.hexdigest(value)[0, 8]}]"
    end

    public_class_method def self.capture(opts = {})
      value = opts[:value]
      return { redacted: redact(value: value), refs: [] } unless value.is_a?(String)

      text = value.to_s
      refs = []
      redacted = PATTERNS.reduce(text.dup) do |acc, (kind, regex)|
        acc.gsub(regex) do |match|
          tok = token(kind: kind, value: match)
          refs << { kind: kind, token: tok }
          PWN::Plugins::Vault.store(label: tok, secret: match, engagement: opts[:engagement]) if opts[:vault] != false && defined?(PWN::Plugins::Vault)
          tok
        rescue StandardError
          tok
        end
      end
      redacted = capture_entropy(text: redacted, refs: refs, vault: opts[:vault], engagement: opts[:engagement]) if opts[:entropy] == true
      { redacted: redacted, refs: refs }
    end

    private_class_method def self.capture_entropy(opts = {})
      text = opts[:text].to_s
      refs = opts[:refs] || []
      text.gsub(%r{[A-Za-z0-9+/=_-]{40,}}) do |match|
        next match if match.start_with?('[REDACTED:')
        next match unless entropy?(text: match)

        tok = token(kind: 'entropy', value: match)
        refs << { kind: 'entropy', token: tok }
        PWN::Plugins::Vault.store(label: tok, secret: match, engagement: opts[:engagement]) if opts[:vault] != false && defined?(PWN::Plugins::Vault)
        tok
      rescue StandardError
        match
      end
    end

    private_class_method def self.entropy?(opts = {})
      s = opts[:text].to_s
      return false if s.length < 40

      freq = s.each_char.tally
      psum = freq.values.sum { |n| (n.to_f / s.length) * Math.log2(n.to_f / s.length) }
      -psum >= 3.5
    end

    public_class_method def self.authors
      "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
    end

    public_class_method def self.help
      puts "USAGE:
        # Recursively redact secret patterns before persistence.
        #{self}.redact(
          value: 'required - string or nested JSON-compatible data'
        )
        # Create a correlatable non-reversible replacement marker.
        #{self}.token(
          kind: 'required - secret type label',
          value: 'required - sensitive value to hash'
        )
        # Capture secrets into Vault labels and return a redacted copy.
        #{self}.capture(
          value: 'required - string that may contain credentials',
          vault: 'optional - false skips Vault.store',
          engagement: 'optional - engagement name stored with the vault label',
          entropy: 'optional - true also captures high-entropy tokens'
        )

        # Print the author information.
        #{self}.authors
      "
    end
  end
end
