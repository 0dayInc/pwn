# frozen_string_literal: true

module PWN
  module AI
    module Agent
      # Coalesce a burst of tool calls into periodic
      # "summary_of_current_task" UI lines without stopping the loop.
      module TaskSummarizer
        DEFAULT_EVERY = 5
        DEFAULT_INTERVAL_S = 8.0
        MAX_BUFFER = 64

        module_function

        def enabled?
          v = PWN::Env.dig(:ai, :agent, :task_summary)
          v.nil? || !!v
        rescue StandardError
          true
        end

        def verbose?
          !!PWN::Env.dig(:ai, :agent, :task_summary_verbose)
        rescue StandardError
          false
        end

        def every_n
          n = PWN::Env.dig(:ai, :agent, :task_summary_every)
          n = DEFAULT_EVERY if n.nil?
          [n.to_i, 1].max
        rescue StandardError
          DEFAULT_EVERY
        end

        def interval_s
          t = PWN::Env.dig(:ai, :agent, :task_summary_interval_s)
          t = DEFAULT_INTERVAL_S if t.nil?
          [t.to_f, 1.0].max
        rescue StandardError
          DEFAULT_INTERVAL_S
        end

        # Per-run state (also safe for nested/swarm if callers keep their own hash)
        def fresh(opts = {})
          {
            request: opts[:request].to_s,
            events: [],
            since_emit: 0,
            last_emit_at: Time.now,
            total: 0,
            counts: Hash.new(0)
          }
        end

        def record!(state, name, args, result)
          return nil unless state

          preview = args.is_a?(String) ? args.to_s[0, 60] : args.inspect[0, 60]
          rs = result.to_s
          ok = !rs.match?(/\A\s*\{?\s*"?(success|ok)"?\s*=>\s*false/i) &&
               !rs.match?(/ERROR:|Traceback|NoMethodError|StandardError/i)
          state[:events] << { name: name.to_s, preview: preview, ok: ok, t: Time.now }
          state[:events].shift while state[:events].size > MAX_BUFFER
          state[:counts][name.to_s] += 1
          state[:total] += 1
          state[:since_emit] += 1

          due = state[:since_emit] >= every_n ||
                (Time.now - state[:last_emit_at]) >= interval_s
          due ? emit!(state) : nil
        end

        def emit!(state, final: false)
          return nil if state.nil? || state[:events].empty?

          counts = state[:counts].sort_by { |_, c| -c }.map { |n, c| "#{n}×#{c}" }
          recent = state[:events].last(every_n)
          focus = recent.map { |e| e[:name] }.uniq.first(4).join(', ')
          fails = state[:events].count { |e| !e[:ok] }
          tail = recent.map { |e| e[:preview] }.compact.reject(&:empty?).last
          bit = tail && !tail.empty? ? "; e.g. #{tail}" : ''
          fail_bit = fails.positive? ? "; failures=#{fails}" : ''
          phase = final ? 'done' : 'in progress'
          state[:since_emit] = 0
          state[:last_emit_at] = Time.now
          "#{phase}: #{focus} — #{state[:total]} tools (#{counts.first(6).join(', ')})#{fail_bit}#{bit}"
        end

        def flush!(state)
          emit!(state, final: true)
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              state = PWN::AI::Agent::TaskSummarizer.fresh(request: 'do the thing')
              line  = PWN::AI::Agent::TaskSummarizer.record!(state, 'shell', 'ls', '{success:true}')
              line  = PWN::AI::Agent::TaskSummarizer.flush!(state)
              PWN::AI::Agent::TaskSummarizer.enabled?
              PWN::AI::Agent::TaskSummarizer.verbose?
              PWN::AI::Agent::TaskSummarizer.every_n
              PWN::AI::Agent::TaskSummarizer.interval_s

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
