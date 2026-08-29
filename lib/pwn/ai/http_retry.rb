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
        return 1 unless opts.is_a?(Hash)

        n = opts[:max_attempts].to_i
        return n if n.positive?
        return 1 if opts[:quiet]
        return 1 if opts[:timeout].to_i.positive? && opts[:timeout].to_i < DEFAULT_TIMEOUT_S

        DEFAULT_MAX_ATTEMPTS
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
        retry_after = 0
        resp = opts[:response]
        retry_after = resp.headers[:retry_after].to_i if resp.respond_to?(:headers) && resp.headers
        retry_after = (0.5 * retry_count) if retry_after.to_f <= 0
        retry_after
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

          # Run retryable and return its result
          #{self}.retryable?(
            error: 'optional - error value consumed by #retryable?',
            message: 'required - message value consumed by #retryable?'
          )

          # Run retry after s and return its result
          #{self}.retry_after_s(
            retry_count: 'optional - retry count value consumed by #retry_after_s',
            response: 'optional - response value consumed by #retry_after_s'
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
