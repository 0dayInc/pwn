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
        #   error: 'optional - String error message when success is false'
        # )

        public_class_method def self.record(opts = {})
          name     = opts[:name].to_s
          success  = opts[:success] ? true : false
          duration = opts[:duration].to_f
          error    = opts[:error]
          return if name.empty?

          metrics = load
          metrics[:tools] ||= {}
          key = name.to_sym
          t = metrics[:tools][key] ||= {
            calls: 0, ok: 0, fail: 0, total_duration: 0.0,
            last_error: nil, last_at: nil
          }
          t[:calls]          += 1
          t[:ok]             += 1 if success
          t[:fail]           += 1 unless success
          t[:total_duration] += duration
          t[:last_error]      = error.to_s[0, 300] if error && !success
          t[:last_at]         = Time.now.utc.iso8601
          save(metrics: metrics)
          t
        end

        # Supported Method Parameters::
        # rows = PWN::AI::Agent::Metrics.summary(
        #   limit: 'optional - cap number of tools returned (default 25)'
        # )

        public_class_method def self.summary(opts = {})
          limit = opts[:limit] || 25
          tools = load[:tools] || {}
          rows = tools.map do |name, t|
            calls = t[:calls].to_i
            ok    = t[:ok].to_i
            rate  = calls.positive? ? (ok.to_f / calls).round(3) : 0.0
            avg   = calls.positive? ? (t[:total_duration].to_f / calls).round(3) : 0.0
            {
              name: name.to_s,
              calls: calls,
              success_rate: rate,
              avg_duration: avg,
              last_error: t[:last_error],
              last_at: t[:last_at]
            }
          end
          rows.sort_by { |r| [-r[:calls], -r[:success_rate]] }.first(limit)
        end

        # Supported Method Parameters::
        # ctx = PWN::AI::Agent::Metrics.to_context(
        #   limit: 'optional - cap number of tools included (default 8)'
        # )

        public_class_method def self.to_context(opts = {})
          limit = opts[:limit] || 8
          rows = summary(limit: limit)
          return '' if rows.empty?

          lines = rows.map do |r|
            err = r[:last_error] ? " last_err=#{r[:last_error][0, 60]}" : ''
            "  - #{r[:name]}: calls=#{r[:calls]} success=#{(r[:success_rate] * 100).round(1)}% avg=#{r[:avg_duration]}s#{err}"
          end
          "TOOL EFFECTIVENESS (historical, adapt tool choice accordingly)\n#{lines.join("\n")}\n\n"
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Metrics.reset

        public_class_method def self.reset
          FileUtils.rm_f(METRICS_FILE)
          { tools: {}, updated_at: nil }
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::Metrics.record(name: 'shell', success: true, duration: 0.42)
              PWN::AI::Agent::Metrics.summary(limit: 10)
              PWN::AI::Agent::Metrics.to_context(limit: 8)   # injected by PromptBuilder
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
