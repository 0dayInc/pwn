# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Metrics is the telemetry layer of the pwn-ai
      # learning loop. Every tool dispatch performed by
      # PWN::AI::Agent::Loop is recorded here (name, success, duration,
      # last error) and persisted to ~/.pwn/metrics.json.
      #
      # PromptBuilder re-injects a compact effectiveness summary into the
      # system prompt on every turn, so the model gains awareness of which
      # tools historically succeed vs. fail on THIS host and can adapt its
      # tool selection accordingly. This is one half of the closed
      # feedback loop that lets pwn-ai continuously make itself smarter
      # (the other half is PWN::AI::Agent::Learning).
      #
      # PER-ENGINE SEGMENTATION
      # -----------------------
      # A local Ollama model and a frontier model do NOT have the same
      # per-tool success rate — blending them mis-advises the local model
      # about itself. Every record now also increments an :engines[<engine>]
      # sub-bucket; summary/to_context accept engine: to surface only that
      # engine's telemetry so the TOOL EFFECTIVENESS block becomes a
      # genuine per-engine learned policy.
      module Metrics
        METRICS_FILE   = File.join(Dir.home, '.pwn', 'metrics.json')
        HALF_LIFE_DAYS = 14.0
        CUSUM_K        = 0.15
        CUSUM_H        = 0.6
        WINDOW         = 30

        # Supported Method Parameters::
        # metrics = PWN::AI::Agent::Metrics.load

        public_class_method def self.load
          FileUtils.mkdir_p(File.dirname(METRICS_FILE))
          return { tools: {}, updated_at: nil } unless File.exist?(METRICS_FILE)

          JSON.parse(File.read(METRICS_FILE), symbolize_names: true)
        rescue StandardError
          { tools: {}, updated_at: nil }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Metrics.save(
        #   metrics: 'required - Hash returned by .load / mutated in place'
        # )

        public_class_method def self.save(opts = {})
          metrics = opts[:metrics] ||= { tools: {} }
          metrics[:updated_at] = Time.now.utc.iso8601
          FileUtils.mkdir_p(File.dirname(METRICS_FILE))
          File.write(METRICS_FILE, JSON.pretty_generate(metrics))
          metrics
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Metrics.record(
        #   name: 'required - tool name that was dispatched',
        #   success: 'required - Boolean, did the handler complete without error',
        #   duration: 'optional - Float seconds the dispatch took',
        #   error: 'optional - String error message when success is false',
        #   engine: 'optional - Symbol/String AI engine that chose this tool (segments telemetry)'
        # )

        public_class_method def self.record(opts = {})
          name     = opts[:name].to_s
          success  = opts[:success] ? true : false
          duration = opts[:duration].to_f
          error    = opts[:error]
          engine   = opts[:engine].to_s
          return if name.empty?

          metrics = load
          metrics[:tools] ||= {}
          key = name.to_sym
          t = metrics[:tools][key] ||= blank_bucket
          bump(bucket: t, success: success, duration: duration, error: error)
          unless engine.empty?
            t[:engines] ||= {}
            e = t[:engines][engine.to_sym] ||= blank_bucket
            bump(bucket: e, success: success, duration: duration, error: error)
          end
          save(metrics: metrics)
          t
        end

        # Supported Method Parameters::
        # rows = PWN::AI::Agent::Metrics.summary(
        #   limit: 'optional - cap number of tools returned (default 25)',
        #   engine: 'optional - only that engine\'s sub-bucket (falls back to global when absent)'
        # )

        public_class_method def self.summary(opts = {})
          limit  = opts[:limit] || 25
          engine = opts[:engine].to_s
          tools  = load[:tools] || {}
          rows = tools.map do |name, t|
            b = engine.empty? ? t : (t.dig(:engines, engine.to_sym) || t)
            calls = b[:calls].to_i
            ok    = b[:ok].to_i
            rate  = calls.positive? ? (ok.to_f / calls).round(3) : 0.0
            avg   = calls.positive? ? (b[:total_duration].to_f / calls).round(3) : 0.0
            {
              name: name.to_s,
              calls: calls,
              success_rate: rate,
              avg_duration: avg,
              last_error: b[:last_error],
              last_at: b[:last_at]
            }
          end
          rows.reject { |r| r[:calls].zero? }
              .sort_by { |r| [-r[:calls], -r[:success_rate]] }.first(limit)
        end

        # Supported Method Parameters::
        # ctx = PWN::AI::Agent::Metrics.to_context(
        #   limit: 'optional - cap number of tools included (default 8)',
        #   engine: 'optional - restrict to one engine\'s telemetry'
        # )

        public_class_method def self.to_context(opts = {})
          limit  = opts[:limit] || 8
          engine = opts[:engine]
          rows   = summary(limit: limit, engine: engine)
          return '' if rows.empty?

          scope = engine.to_s.empty? ? 'historical' : "engine=#{engine}"
          lines = rows.map do |r|
            err = r[:last_error] ? " last_err=#{r[:last_error][0, 60]}" : ''
            "  - #{r[:name]}: calls=#{r[:calls]} success=#{(r[:success_rate] * 100).round(1)}% avg=#{r[:avg_duration]}s#{err}"
          end
          "TOOL EFFECTIVENESS (#{scope}, adapt tool choice accordingly)\n#{lines.join("\n")}\n\n"
        end

        # Supported Method Parameters::
        # score = PWN::AI::Agent::Metrics.ucb(
        #   name: 'required - tool name',
        #   c: 'optional - exploration constant (default 1.4)'
        # )
        #
        # C1 — Upper Confidence Bound. Tools with few calls get an
        # exploration bonus so a single early failure (before its dep was
        # installed) does NOT permanently blacklist it. Registry.rank uses
        # this instead of raw success_rate.

        public_class_method def self.ucb(opts = {})
          name = opts[:name].to_s
          c    = (opts[:c] || 1.4).to_f
          data = load[:tools] || {}
          t    = data[name.to_sym] || blank_bucket
          n    = [t[:calls].to_f, 1.0].max
          total = [data.values.sum { |v| v[:calls].to_f }, 1.0].max
          mean  = t[:ok].to_f / n
          mean + (c * Math.sqrt(Math.log(total) / n))
        rescue StandardError
          1.0
        end

        # Supported Method Parameters::
        # p = PWN::AI::Agent::Metrics.thompson(name: 'shell')
        #
        # C1 — Thompson sample from Beta(ok+1, fail+1). Naturally balances
        # exploit/explore; used by Registry.rank as the tie-breaker.

        public_class_method def self.thompson(opts = {})
          t = (load[:tools] || {})[opts[:name].to_s.to_sym] || blank_bucket
          beta_sample(alpha: t[:ok].to_f + 1.0, beta: t[:fail].to_f + 1.0)
        rescue StandardError
          0.5
        end

        # Supported Method Parameters::
        # a = PWN::AI::Agent::Metrics.advantage(name: 'shell')
        #
        # C1 — tool.success_rate − global_rate over the rolling window.

        public_class_method def self.advantage(opts = {})
          data = load[:tools] || {}
          t    = data[opts[:name].to_s.to_sym]
          return 0.0 unless t

          global = data.values.sum { |v| v[:ok].to_f } / [data.values.sum { |v| v[:calls].to_f }, 1.0].max
          win    = Array(t[:window])
          local  = win.empty? ? (t[:ok].to_f / [t[:calls].to_f, 1.0].max) : (win.sum.to_f / win.length)
          (local - global).round(3)
        rescue StandardError
          0.0
        end

        # Supported Method Parameters::
        # cps = PWN::AI::Agent::Metrics.changepoints
        #
        # E1 — tools whose CUSUM tripped (success_rate regime change). The
        # caller (Mistakes.record / Curriculum) triggers extro_snapshot +
        # correlate on these so a Mistake caused by env drift is tagged
        # cause: :env_drift and does NOT count toward [REPEATING].

        public_class_method def self.changepoints(opts = {})
          within = (opts[:within_secs] || 3_600).to_i
          now = Time.now.utc
          (load[:tools] || {}).filter_map do |name, t|
            cp = t[:changepoint_at]
            next unless cp && (now - Time.parse(cp)) < within

            { name: name.to_s, at: cp, window_rate: Array(t[:window]).sum.to_f / [Array(t[:window]).length, 1].max }
          end
        rescue StandardError
          []
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Metrics.record_calibration(predicted:, actual:, brier:, engine:)
        #
        # W3 — plan_first emits p(success); Loop.run calls this with the
        # realised outcome. Tracked per-engine so calibration of the local
        # LoRA vs frontier is comparable.

        public_class_method def self.record_calibration(opts = {})
          m = load
          m[:calibration] ||= {}
          eng = (opts[:engine] || :global).to_s.to_sym
          c = m[:calibration][eng] ||= { n: 0, brier_sum: 0.0, p_sum: 0.0, a_sum: 0.0 }
          c[:n]         += 1
          c[:brier_sum] += opts[:brier].to_f
          c[:p_sum]     += opts[:predicted].to_f
          c[:a_sum]     += opts[:actual].to_f
          save(metrics: m)
          c
        end

        # Supported Method Parameters::
        # cal = PWN::AI::Agent::Metrics.calibration(engine: :ollama)

        public_class_method def self.calibration(opts = {})
          eng = (opts[:engine] || :global).to_s.to_sym
          c = (load[:calibration] || {})[eng]
          return { n: 0, brier: nil } unless c && c[:n].to_i.positive?

          n = c[:n].to_f
          { n: c[:n], brier: (c[:brier_sum] / n).round(4), mean_predicted: (c[:p_sum] / n).round(3), mean_actual: (c[:a_sum] / n).round(3), overconfidence: ((c[:p_sum] - c[:a_sum]) / n).round(3) }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Metrics.reset

        public_class_method def self.reset
          FileUtils.rm_f(METRICS_FILE)
          { tools: {}, updated_at: nil }
        end

        private_class_method def self.blank_bucket
          { calls: 0, ok: 0, fail: 0, total_duration: 0.0, last_error: nil, last_at: nil, window: [], cusum_lo: 0.0, cusum_hi: 0.0 }
        end

        # Marsaglia-Tsang gamma → Beta(a,b) sampler; no external gem.
        private_class_method def self.beta_sample(opts = {})
          a = gamma_sample(shape: opts[:alpha])
          b = gamma_sample(shape: opts[:beta])
          a / (a + b)
        end

        private_class_method def self.gamma_sample(opts = {})
          k = opts[:shape].to_f
          return gamma_sample(shape: k + 1.0) * (rand**(1.0 / k)) if k < 1.0

          d = k - (1.0 / 3.0)
          c = 1.0 / Math.sqrt(9.0 * d)
          loop do
            x = Math.sqrt(-2.0 * Math.log(rand)) * Math.cos(2.0 * Math::PI * rand)
            v = (1.0 + (c * x))**3
            next if v <= 0

            u = rand
            return d * v if Math.log(u) < (0.5 * x * x) + d - (d * v) + (d * Math.log(v))
          end
        end

        private_class_method def self.bump(opts = {})
          b        = opts[:bucket]
          success  = opts[:success]
          duration = opts[:duration].to_f
          error    = opts[:error]
          decay(bucket: b)
          b[:calls]          += 1
          b[:ok]             += 1 if success
          b[:fail]           += 1 unless success
          b[:total_duration]  = b[:total_duration].to_f + duration
          b[:last_error]      = error.to_s[0, 300] if error && !success
          b[:last_at]         = Time.now.utc.iso8601
          # Rolling window for changepoint / advantage estimation
          b[:window] = (Array(b[:window]) + [success ? 1 : 0]).last(WINDOW)
          # E1 — CUSUM changepoint on success_rate
          mean = b[:calls].positive? ? b[:ok].to_f / b[:calls] : 0.5
          x = success ? 1.0 : 0.0
          b[:cusum_lo] = [0.0, b[:cusum_lo].to_f + (mean - x - CUSUM_K)].max
          b[:cusum_hi] = [0.0, b[:cusum_hi].to_f + (x - mean - CUSUM_K)].max
          if b[:cusum_lo] > CUSUM_H || b[:cusum_hi] > CUSUM_H
            b[:changepoint_at] = Time.now.utc.iso8601
            b[:cusum_lo] = 0.0
            b[:cusum_hi] = 0.0
          end
          b
        end

        # Exponential decay so a mistake from months ago on a since-rewritten
        # module stops dominating the policy. Applied lazily on bump.
        private_class_method def self.decay(opts = {})
          b = opts[:bucket]
          last = b[:last_at]
          return unless last

          days = (Time.now.utc - Time.parse(last)) / 86_400.0
          return if days < 1.0

          f = 0.5**(days / HALF_LIFE_DAYS)
          %i[calls ok fail total_duration].each { |k| b[k] = (b[k].to_f * f) }
        rescue StandardError
          nil
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::Metrics.record(name: 'shell', success: true, duration: 0.42, engine: :ollama)
              PWN::AI::Agent::Metrics.summary(limit: 10, engine: :ollama)
              PWN::AI::Agent::Metrics.to_context(limit: 8, engine: :ollama)   # injected by PromptBuilder
              PWN::AI::Agent::Metrics.ucb(name: 'shell')                 # C1 exploration bonus
              PWN::AI::Agent::Metrics.thompson(name: 'shell')            # C1 Beta(ok+1,fail+1) sample
              PWN::AI::Agent::Metrics.advantage(name: 'shell')           # C1 local − global
              PWN::AI::Agent::Metrics.changepoints(within_secs: 3600)    # E1 CUSUM regime changes
              PWN::AI::Agent::Metrics.record_calibration(predicted: 0.8, actual: 1.0, brier: 0.04, engine: :ollama)
              PWN::AI::Agent::Metrics.calibration(engine: :ollama)       # W3 Brier / overconfidence
              PWN::AI::Agent::Metrics.reset
              PWN::AI::Agent::Metrics.load
              PWN::AI::Agent::Metrics.save(metrics: hash)

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
