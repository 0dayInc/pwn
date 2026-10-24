# frozen_string_literal: true

module PWN
  module AI
    # Shared REST timeout / 429 / ReadTimeout policy for every AI provider.
    # Default wall clock per attempt is 180s with up to 5 attempts (≈900s total).
    # Short quiet sidecar hops stay single-shot.
    module HttpRetry
      DEFAULT_TIMEOUT_S = 180
      DEFAULT_MAX_ATTEMPTS = 5

      public_class_method def self.timeout_s(opts = {})
        return DEFAULT_TIMEOUT_S unless opts.is_a?(Hash)

        t = opts[:timeout].to_i
        t.positive? ? t : DEFAULT_TIMEOUT_S
      end

      public_class_method def self.max_attempts(opts = {})
        return 1 if Thread.current[:pwn_provider_attempt_owner] || Thread.current[:pwn_request_runtime]
        return 1 unless opts.is_a?(Hash)

        n = opts[:max_attempts].to_i
        return n if n.positive?
        return 1 if opts[:quiet]
        return 1 if opts[:timeout].to_i.positive? && opts[:timeout].to_i < DEFAULT_TIMEOUT_S

        DEFAULT_MAX_ATTEMPTS
      end

      # Resolve provider defaults from the active request without mutating Env.
      public_class_method def self.provider_config(opts = {})
        engine = opts[:engine]
        title_config = Thread.current[:pwn_session_title_config]
        return title_config[engine] if title_config

        owner = Thread.current[:pwn_request_runtime]
        return owner.provider_config(engine) if owner.respond_to?(:provider_config)

        defined?(PWN::Env) ? PWN::Env[:ai]&.[](engine) : nil
      end

      public_class_method def self.retryable?(opts = {})
        err = opts[:error]
        msg = err.respond_to?(:message) ? err.message.to_s : err.to_s
        msg = opts[:message].to_s if msg.empty?
        msg.match?(/HTTP 50[234]|Gateway Time-out|stream absolute timeout|ReadTimeout|Net::ReadTimeout|Timed out reading/i)
      rescue StandardError
        false
      end

      public_class_method def self.retry_after_s(opts = {})
        retry_count = [opts[:retry_count].to_i, 1].max
        headers = {}
        resp = opts[:response]
        headers = resp.headers if resp.respond_to?(:headers) && resp.headers
        ra = headers[:retry_after] || headers['retry-after'] || headers['Retry-After']
        if ra.to_s.match?(/\A\d+(\.\d+)?\z/)
          n = ra.to_f
          return n if n.positive?
        end

        [2**retry_count, 60].min.to_f
      end

      public_class_method def self.quota_exhausted?(opts = {})
        err = opts[:error]
        blob = err.respond_to?(:message) ? err.message.to_s : err.to_s
        blob = opts[:message].to_s if blob.empty?
        if err.respond_to?(:response) && err.response
          blob = "#{blob} #{err.response}"
          blob = "#{blob} #{err.response.body}" if err.response.respond_to?(:body)
        end
        blob.match?(/insufficient_quota|credit_balance_exhausted|exceeded your current quota|billing_not_active|spend.?limit|no credits remaining/i)
      rescue StandardError
        false
      end

      public_class_method def self.quota_message(opts = {})
        err = opts[:error]
        blob = ''
        blob = err.message.to_s if err.respond_to?(:message)
        if err.respond_to?(:response) && err.response
          blob = "#{blob} #{err.response}"
          blob = "#{blob} #{err.response.body}" if err.response.respond_to?(:body)
        end
        blob = opts[:message].to_s if blob.strip.empty?
        url = blob[%r{https://platform\.openai\.com/settings/organization/billing/?}] ||
              'https://platform.openai.com/settings/organization/billing/'
        'OpenAI API has no credits (insufficient_quota / credit_balance_exhausted). ' \
          "Add prepaid API credits at #{url} — a ChatGPT Plus/Pro plan does not fund api.openai.com. " \
          'Then retry; /model openai stays selected.'
      end

      # Tees provider REST events into the open pwn-ai DEBUG RN log and STDERR.
      public_class_method def self.report_event(opts = {})
        return unless opts.is_a?(Hash)

        label = opts[:label].to_s
        label = 'ai' if label.empty?
        err = opts[:error]
        extra = opts[:extra].to_s
        meth = opts[:http_method].to_s.upcase
        call = opts[:rest_call].to_s
        klass = err ? err.class : 'Error'
        msg = err ? err.message : extra
        line = "[pwn-ai/#{label}] #{klass}: #{msg} (#{meth} #{call} #{extra})".strip
        which = opts[:which_self] || self
        PWN::Plugins::Log.progress(msg: line, which_self: which, cap: 0) if defined?(PWN::Plugins::Log) && PWN::Plugins::Log.debug_enabled?
        warn line unless opts[:quiet]
        line
      end

      public_class_method def self.authors
        "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
      end

      public_class_method def self.help
        puts "USAGE:
          # Run timeout s and return its result
          #{self}.timeout_s(
            timeout: 'optional - seconds to wait before giving up'
          )

          # Run max attempts and return its result
          #{self}.max_attempts(
            max_attempts: 'optional - max attempts value consumed by #max_attempts',
            quiet: 'optional - quiet value consumed by #max_attempts',
            timeout: 'optional - seconds to wait before giving up'
          )

          # Resolve isolated provider configuration for the active request.
          #{self}.provider_config(
            engine: 'required - provider symbol whose request-owned defaults to read'
          )
          # Run retryable and return its result
          #{self}.retryable?(
            error: 'optional - error value consumed by #retryable?',
            message: 'required - message value consumed by #retryable?'
          )

          # Seconds to sleep after a 429 (Retry-After, else exponential 2..60).
          #{self}.retry_after_s(
            retry_count: 'optional - 1-based attempt used for exponential fallback',
            response: 'optional - RestClient response with Retry-After header'
          )

          # True when a 429 body is billing/quota, not a retryable rate limit.
          #{self}.quota_exhausted?(
            error: 'optional - exception whose message/response body is inspected',
            message: 'optional - raw error text when error is omitted'
          )

          # Operator-facing line for a billing/quota 429 (do not retry).
          #{self}.quota_message(
            error: 'optional - exception whose response body may contain the billing URL',
            message: 'optional - raw error text when error is omitted'
          )

          # Tees provider REST events into the open pwn-ai DEBUG RN log and STDERR
          #{self}.report_event(
            label: 'required - label value consumed by #report_event',
            error: 'optional - error value consumed by #report_event',
            extra: 'optional - extra value consumed by #report_event',
            http_method: 'optional - http method value consumed by #report_event',
            rest_call: 'optional - rest call value consumed by #report_event',
            which_self: 'optional - which self value consumed by #report_event (defaults to self)',
            quiet: 'optional - quiet value consumed by #report_event'
          )

          # Print the AUTHOR(S) string for this module.
          #{self}.authors
        "
        constants.sort
      end
    end
  end
end
