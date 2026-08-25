# frozen_string_literal: true

require 'digest'

module PWN
  module AI
    module Agent
      # Shared pre-dispatch guards for the two high-volume runtime tools
      # (shell / pwn_eval). Rejects placeholder payloads, aliases wrong
      # schema keys, and names the shell that will actually run the command.
      module ToolGuard
        ALIASES = {
          'command' => %w[value cmd input],
          'code' => %w[value source ruby input],
          'query' => %w[value q text]
        }.freeze

        # Token-level junk the model keeps emitting instead of a real command.
        PLACEHOLDER_RX = /
          \A\s*(?:\.{3}|…|\{\s*\.{3}\s*\}|\{\s*…\s*\}|<\.{3}>)\s*\z
          |(?:^|[\s;|&])(?:\.{3}|…|\{\s*\.{3}\s*\}|\{\s*…\s*\})(?:$|[\s;|&])
        /x

        # Conservative bash-only constructs. POSIX `$(())` is allowed.
        BASHISM_RX = /
          \bPIPESTATUS\b
          |\$\{?RANDOM\}?\b
          |\[\[(?:\s|\z)
          |(?:^|[\s;|&])source\s+\S
          |<\([^)]
          |&>
        /x

        public_class_method def self.present?(opts = {})
          value = opts.is_a?(Hash) ? opts[:value] : opts
          !value.nil? && !value.to_s.strip.empty?
        end

        public_class_method def self.placeholder?(opts = {})
          PLACEHOLDER_RX.match?(opts[:text].to_s)
        rescue StandardError
          false
        end

        public_class_method def self.bashism?(opts = {})
          BASHISM_RX.match?(opts[:text].to_s)
        rescue StandardError
          false
        end

        public_class_method def self.shell_bash?
          v = (PWN::Env.dig(:ai, :agent, :shell_bash) if defined?(PWN::Env))
          v == true || v.to_s.match?(/\A(1|true|yes|on)\z/i)
        rescue StandardError
          false
        end

        public_class_method def self.shell_name
          shell_bash? ? 'bash -lc' : '/bin/sh'
        end

        # Coerce common wrong keys onto the first required schema field.
        # Returns the args hash; sets :__schema_error when still missing.
        public_class_method def self.coerce_args(opts = {})
          args = (opts[:args] || {}).dup
          args = args.each_with_object({}) { |(k, v), m| m[k.to_sym] = v } unless args.empty?
          req = Array(opts[:required]).map(&:to_s)
          req.each do |key|
            next if present?(value: args[key.to_sym])

            hit = Array(ALIASES[key]).find { |a| present?(value: args[a.to_sym]) }
            args[key.to_sym] = args[hit.to_sym] if hit
          end
          missing = req.reject { |k| present?(value: args[k.to_sym]) }
          unless missing.empty?
            args[:__schema_error] = "missing required #{missing.join(', ')}"
            args[:__expected] = req
            args[:__schema_hint] =
              "Expected keys: #{req.join(', ')}. " \
              'Do not send value/placeholder/ellipsis. ' \
              'Example: shell(command="uname -r") or pwn_eval(code="1+1").'
          end
          args
        rescue StandardError
          opts[:args] || {}
        end

        public_class_method def self.invalid_payload(opts = {})
          hint = opts[:hint].to_s
          {
            stdout: '',
            stderr: hint,
            exit: 2,
            error: 'invalid_payload',
            hint: hint,
            shell: opts[:shell] || shell_name
          }
        end

        public_class_method def self.host_load(opts = {})
          return { ncpu: 1, load1: 0.0, mem_avail_mb: 0 } unless opts.is_a?(Hash)

          ncpu = File.readable?('/proc/cpuinfo') ? File.read('/proc/cpuinfo').scan(/^processor/).size : 0
          ncpu = 1 if ncpu < 1
          load1 = 0.0
          load1 = File.read('/proc/loadavg').to_s.split[0].to_f if File.readable?('/proc/loadavg')
          avail = 0
          if File.readable?('/proc/meminfo')
            File.foreach('/proc/meminfo') do |ln|
              next unless ln.start_with?('MemAvailable:')

              avail = ln.split[1].to_i / 1024
              break
            end
          end
          { ncpu: ncpu, load1: load1, mem_avail_mb: avail }
        rescue StandardError
          { ncpu: 1, load1: 0.0, mem_avail_mb: 0 }
        end

        TIMEOUT_STEP_S = 180
        TIMEOUT_MAX_S = 10_800
        MUTATION_MAX = 10

        # Conservative wall-clock seconds for shell / pwn_eval.
        # Explicit timeout is honored for any payload (1..TIMEOUT_MAX_S).
        # Omit → host-derived default from loadavg / ncpu / MemAvailable.
        # No tool-name sniffing: a 65k scan and `ls` use the same math.
        public_class_method def self.deadline_s(opts = {})
          kind = opts[:kind].to_s.to_sym
          asked = opts[:timeout] || opts[:timeout_s]
          asked_i = asked.to_i
          return asked_i.clamp(1, TIMEOUT_MAX_S) if asked_i.positive?

          snap = host_load
          ncpu = [snap[:ncpu].to_i, 1].max
          load1 = snap[:load1].to_f
          mem = snap[:mem_avail_mb].to_i
          default_max = kind == :shell ? 180 : 90
          base = kind == :shell ? 30 : 20
          base += 15 if load1 > ncpu
          base += 10 if load1 > (ncpu * 1.5)
          base += 10 if mem.positive? && mem < 512
          base.clamp(8, default_max)
        end

        public_class_method def self.reset_timeout_budget(opts = {})
          return :noop unless opts.is_a?(Hash)

          @timeout_spent = {}
          @timeout_mutations = {}
          @timeout_mutated = {}
          :reset
        end

        public_class_method def self.reset_timeout_budget!
          reset_timeout_budget
        end

        public_class_method def self.mutation_count(opts = {})
          return 0 unless opts.is_a?(Hash)

          timeout_mutations[task_key(opts)].to_i
        end

        public_class_method def self.payload_spent(opts = {})
          return 0 unless opts.is_a?(Hash)

          timeout_spent[payload_key(opts)].to_i
        end

        public_class_method def self.note_timeout!(opts = {})
          return 0 unless opts.is_a?(Hash)

          timeout = opts[:timeout].to_i
          timeout = 1 if timeout < 1
          key = payload_key(opts)
          timeout_spent[key] = timeout_spent[key].to_i + timeout
          if budget_exhausted?(opts.merge(spent: timeout_spent[key])) && !timeout_mutated[key]
            timeout_mutated[key] = true
            tkey = task_key(opts)
            timeout_mutations[tkey] = timeout_mutations[tkey].to_i + 1
          end
          timeout_spent[key]
        end

        public_class_method def self.next_timeout(opts = {})
          base = opts[:timeout].to_i
          base = 1 if base < 1
          spent = opts.key?(:spent) ? opts[:spent].to_i : payload_spent(opts)
          remaining = TIMEOUT_MAX_S - spent
          remaining = 0 if remaining.negative?
          [base + TIMEOUT_STEP_S, remaining, TIMEOUT_MAX_S].min
        end

        # Timeout policy (loop-law, not a skill):
        # 1. Same payload: timeout += 180 until the 3-hour budget is gone.
        # 2. At the 3-hour cap: rewrite ruby/command for the same goal
        #    (one mutation). Max MUTATION_MAX mutations per task.
        # 3. After MUTATION_MAX mutations: stop (exhausted).
        public_class_method def self.timeout_lesson(opts = {})
          return { scenario: :construction, error: '', hint: '' } unless opts.is_a?(Hash)

          tool = opts[:tool].to_s
          timeout = opts[:timeout].to_i
          spent = payload_spent(opts)
          spent_after = spent >= timeout && timeout.positive? ? spent : spent + [timeout, 1].max
          nxt = next_timeout(timeout: timeout, spent: spent_after)
          mutations = mutation_count(opts)
          if budget_exhausted?(opts.merge(timeout: timeout, spent: spent_after))
            if mutations >= MUTATION_MAX
              {
                scenario: :exhausted,
                error: "#{tool} timeout: #{MUTATION_MAX} mutations exhausted for this task",
                hint: "This task hit the mutation cap (#{MUTATION_MAX} rewrites after " \
                      '3-hour budgets). Do not retry the same payload. Report what ' \
                      'was tried and what remains blocked.'
              }
            else
              {
                scenario: :construction,
                error: "#{tool} timeout: 3-hour budget exhausted; reconstruct payload to same goal",
                hint: "The #{tool} payload used its 3-hour budget. Generate different " \
                      'ruby/command for the same goal. Mutation ' \
                      "#{[mutations, 1].max}/#{MUTATION_MAX}."
              }
            end
          else
            {
              scenario: :deadline,
              error: "#{tool} timeout: deadline too short; retry with timeout += 180",
              hint: "Keep the same #{tool} payload. This timeout (#{timeout}s) was too " \
                    "short. Retry with timeout += 180 (next_timeout=#{nxt})."
            }
          end
        end

        public_class_method def self.timeout_result(opts = {})
          return { stdout: '', stderr: '', exit: nil, error: 'timeout', scenario: :deadline, hint: '', next_timeout: TIMEOUT_STEP_S, shell: shell_name } unless opts.is_a?(Hash)

          timeout = opts[:timeout].to_i
          note_timeout!(opts)
          lesson = timeout_lesson(
            tool: opts[:tool],
            payload: opts[:payload],
            timeout: timeout,
            task: opts[:task]
          )
          {
            stdout: opts[:stdout].to_s,
            stderr: opts[:stderr].to_s,
            exit: nil,
            error: "timeout after #{timeout}s",
            scenario: lesson[:scenario],
            hint: lesson[:hint],
            next_timeout: next_timeout(timeout: timeout, spent: payload_spent(opts)),
            mutations: mutation_count(opts),
            shell: opts[:shell] || shell_name
          }
        end

        private_class_method def self.timeout_spent
          @timeout_spent ||= {}
        end

        private_class_method def self.timeout_mutations
          @timeout_mutations ||= {}
        end

        private_class_method def self.timeout_mutated
          @timeout_mutated ||= {}
        end

        private_class_method def self.task_key(opts = {})
          t = opts[:task]
          t = opts[:session_id] if t.to_s.strip.empty?
          t.to_s.strip.empty? ? 'default' : t.to_s
        end

        private_class_method def self.payload_key(opts = {})
          payload = opts[:payload].to_s
          "#{task_key(opts)}:#{Digest::SHA256.hexdigest(payload)}"
        end

        private_class_method def self.budget_exhausted?(opts = {})
          spent = opts[:spent]
          spent = payload_spent(opts) if spent.nil?
          opts[:timeout].to_i >= TIMEOUT_MAX_S || spent.to_i >= TIMEOUT_MAX_S
        end

        public_class_method def self.timeout_prior_count(opts = {})
          return 0 unless opts.is_a?(Hash)
          return 0 unless defined?(PWN::AI::Agent::Mistakes)

          tool = opts[:tool].to_s
          PWN::AI::Agent::Mistakes.for_tool(tool: tool, unresolved_only: true).count do |m|
            m[:shape].to_s == 'timeout' || m[:error].to_s.match?(/timeout/)
          end
        rescue StandardError
          0
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::ToolGuard.placeholder?(text: '...')
              PWN::AI::Agent::ToolGuard.coerce_args(args: { value: 'id' }, required: %w[command])
              #{self}.authors
          USAGE
        end
      end
    end
  end
end
