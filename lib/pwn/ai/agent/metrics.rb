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
      # A local qwen3.6:35b and a frontier model do NOT have the same
      # per-tool success rate — blending them mis-advises the local model
      # about itself. Every record now also increments an :engines[<engine>]
      # sub-bucket; summary/to_context accept engine: to surface only that
      # engine's telemetry so the TOOL EFFECTIVENESS block becomes a
      # genuine per-engine learned policy.
      module Metrics
        METRICS_FILE = File.join(Dir.home, '.pwn', 'metrics.json')

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
        # PWN::AI::Agent::Metrics.reset

        public_class_method def self.reset
          FileUtils.rm_f(METRICS_FILE)
          { tools: {}, updated_at: nil }
        end

        private_class_method def self.blank_bucket
          { calls: 0, ok: 0, fail: 0, total_duration: 0.0, last_error: nil, last_at: nil }
        end

        private_class_method def self.bump(opts = {})
          b        = opts[:bucket]
          success  = opts[:success]
          duration = opts[:duration].to_f
          error    = opts[:error]
          b[:calls]          += 1
          b[:ok]             += 1 if success
          b[:fail]           += 1 unless success
          b[:total_duration]  = b[:total_duration].to_f + duration
          b[:last_error]      = error.to_s[0, 300] if error && !success
          b[:last_at]         = Time.now.utc.iso8601
          b
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
