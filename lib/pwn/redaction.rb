# frozen_string_literal: true

require 'digest'
require 'json'

module PWN
  # Write-boundary redaction; redact never opens a credential store. Capture optionally stores ordinary secrets. Hardware/MFA fields use constant masks, never digest markers or loot capture.
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
    CONSTANT_MASK = '[REDACTED]'
    MASKED_NAME = /(?:
      (?:(?:new|current|old|admin|user|fido2?|piv|openpgp)[_-])?(?:pin|puk) |
      access[_-]?code | management[_-]?(?:key|password) | oath[_-]?secret | static[_-]?password |
      scp(?:03|11)?(?:[_-](?:key|keys|enc|mac|dek)(?:[_-]key)?)? |
      (?:mfa|otp|totp|hotp)(?:[_-](?:code|token|secret))? | (?:recovery|verification)[_-]?code
    )/ix
    MASKED_FIELD = /\A#{MASKED_NAME}\z/
    MASKED_TEXT = /(?<![\w-])((?:--)?["']?#{MASKED_NAME}["']?\s*(?:=>|[:=])\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\[REDACTED(?::[^\]]+)?\]|[^\s,;}\])]+)/

    public_class_method def self.redact(opts = {})
      value = opts[:value]
      validate_nesting(value: value)
      redact_value(value: value)
    end

    # Check secret containers too, before their existing token/inspect path.
    private_class_method def self.validate_nesting(opts = {})
      value = opts[:value]
      depth = opts.fetch(:depth, 0)
      return unless value.is_a?(Hash) || value.is_a?(Array)
      raise JSON::NestingError, 'redaction input exceeds JSON nesting limit (100)' if depth >= 100

      if value.is_a?(Hash)
        value.each do |key, item|
          validate_nesting(value: key, depth: depth + 1)
          validate_nesting(value: item, depth: depth + 1)
        end
      else
        value.each { |item| validate_nesting(value: item, depth: depth + 1) }
      end
    end

    private_class_method def self.redact_value(opts = {})
      value = opts[:value]
      case value
      when Hash
        value.to_h do |key, item|
          clean = if key.to_s.match?(MASKED_FIELD) && !item.nil?
                    CONSTANT_MASK
                  elsif key.to_s.match?(SECRET_FIELD) && !item.nil?
                    token(kind: key.to_s.downcase, value: item.to_s)
                  else
                    redact_value(value: item)
                  end
          [key.is_a?(String) ? redact_value(value: key) : key, clean]
        end
      when Array then value.map { |item| redact_value(value: item) }
      when String
        PATTERNS.reduce(mask_fields(text: value)) do |text, (kind, regex)|
          text.split(/(\[REDACTED(?::[^:\]]+:[0-9a-f]{8})?\])/).map do |part|
            part.start_with?('[REDACTED') ? part : part.gsub(regex) { |match| token(kind: kind, value: match) }
          end.join
        end
      else value
      end
    end

    private_class_method def self.mask_fields(opts = {})
      text = opts[:text]
      clean = +''
      offset = 0
      while (match = MASKED_TEXT.match(text, offset))
        clean << text[offset...match.begin(0)] << match[1] << CONSTANT_MASK
        offset = masked_value_end(text: text, start: match.end(1), finish: match.end(0))
      end
      clean << text[offset..]
    end

    # Iterative scan prevents partial masks of serialized arrays/hashes of keys.
    private_class_method def self.masked_value_end(opts = {})
      text = opts[:text]
      start = opts[:start]
      pairs = { '[' => ']', '{' => '}' }
      return opts[:finish] unless pairs.key?(text[start]) || ['"', "'"].include?(text[start])

      stack = []
      quote = nil
      escaped = false
      text[start..].each_char.with_index(start) do |char, index|
        if quote
          if escaped
            escaped = false
          elsif char == '\\'
            escaped = true
          elsif char == quote
            quote = nil
            return index + 1 if stack.empty?
          end
        elsif ['"', "'"].include?(char)
          quote = char
        elsif pairs.key?(char)
          stack << pairs[char]
        elsif pairs.value?(char)
          return text.length unless stack.pop == char
          return index + 1 if stack.empty?
        end
      end
      text.length
    end

    public_class_method def self.token(opts = {})
      value = opts[:value].to_s
      return value if value.match?(/\A\[REDACTED:[^:]+:[0-9a-f]{8}\]\z/)

      "[REDACTED:#{opts[:kind]}:#{Digest::SHA256.hexdigest(value)[0, 8]}]"
    end

    public_class_method def self.capture(opts = {})
      value = opts[:value]
      return { redacted: redact(value: value), refs: [] } unless value.is_a?(String)

      text = mask_fields(text: value)
      refs = []
      redacted = PATTERNS.reduce(text.dup) do |acc, (kind, regex)|
        acc.gsub(regex) do |match|
          next match if match.match?(/\A[\w-]+\s*[:=]\s*\[REDACTED\]\z/)

          tok = token(kind: kind, value: match)
          refs << { kind: kind, token: tok }
          PWN::Plugins::Vault.store(label: tok, secret: match, engagement: opts[:engagement], yubikey: opts[:yubikey]) if opts[:vault] != false && defined?(PWN::Plugins::Vault)
          tok
        rescue StandardError
          tok
        end
      end
      redacted = capture_entropy(text: redacted, refs: refs, vault: opts[:vault], engagement: opts[:engagement], yubikey: opts[:yubikey]) if opts[:entropy] == true
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
        PWN::Plugins::Vault.store(label: tok, secret: match, engagement: opts[:engagement], yubikey: opts[:yubikey]) if opts[:vault] != false && defined?(PWN::Plugins::Vault)
        tok
      rescue StandardError
        tok || token(kind: 'entropy', value: match)
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
        # Redact before persistence; hardware/MFA fields use constant masks. Reject cycles/depth above 100 with JSON::NestingError.
        #{self}.redact(
          value: 'required - string or nested JSON-compatible data'
        )
        # Create a correlatable non-reversible replacement marker.
        #{self}.token(
          kind: 'required - secret type label',
          value: 'required - sensitive value to hash'
        )
        # Capture ordinary secrets into Vault labels; mask hardware/MFA fields without storing them.
        #{self}.capture(
          value: 'required - string that may contain credentials',
          vault: 'optional - false skips Vault.store',
          yubikey: 'optional - selector Hash for hardware-encrypted captured loot; no software fallback on failure',
          engagement: 'optional - engagement name stored with the vault label',
          entropy: 'optional - true also captures high-entropy tokens'
        )

        # Print the author information.
        #{self}.authors
      "
    end
  end
end
