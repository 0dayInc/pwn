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
        puts <<~USAGE
          USAGE:
            PWN::AI::HttpRetry.timeout_s(timeout: nil)         # => 180
            PWN::AI::HttpRetry.max_attempts(quiet: false)      # => 5
            PWN::AI::HttpRetry.report_event(
              label: 'grok',
              error: e,
              http_method: :post,
              rest_call: 'chat/completions'
            )
            #{self}.authors
        USAGE
      end
    end
  end
end
