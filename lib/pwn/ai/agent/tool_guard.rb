# frozen_string_literal: true

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

        # Conservative wall-clock seconds for shell / pwn_eval.
        # Explicit model estimate is honored then clamped. Omit → host-derived
        # default from loadavg / ncpu / MemAvailable (loaded hosts get a bit
        # more time, still capped).
        public_class_method def self.deadline_s(opts = {})
          kind = opts[:kind].to_s.to_sym
          max = kind == :shell ? 180 : 90
          asked = opts[:timeout] || opts[:timeout_s]
          asked_i = asked.to_i
          if asked_i.positive?
            lo = 1
            hi = max
            return asked_i.clamp(lo, hi)
          end

          snap = host_load
          ncpu = [snap[:ncpu].to_i, 1].max
          load1 = snap[:load1].to_f
          mem = snap[:mem_avail_mb].to_i
          base = kind == :shell ? 30 : 20
          base += 15 if load1 > ncpu
          base += 10 if load1 > (ncpu * 1.5)
          base += 10 if mem.positive? && mem < 512
          base.clamp(8, max)
        end

        # Two-scenario timeout policy (loop-law, not a skill):
        # 1. First timeout → reconstruct the ruby/command for the same goal.
        #    Do not first raise timeout.
        # 2. A later timeout of the same tool → deadline was too short; raise
        #    a conservative HOST LOAD timeout (still clamped).
        public_class_method def self.timeout_lesson(opts = {})
          return { scenario: :construction, error: '', hint: '' } unless opts.is_a?(Hash)

          tool = opts[:tool].to_s
          timeout = opts[:timeout].to_i
          prior = timeout_prior_count(tool: tool)
          if prior.positive?
            {
              scenario: :deadline,
              error: "#{tool} timeout: deadline too short; raise conservative HOST LOAD timeout",
              hint: "Scenario 2: the #{tool} payload already timed out once. " \
                    "This timeout (#{timeout}s) was too short. Raise a conservative " \
                    'timeout from HOST LOAD (clamped). Record this so it does not recur. ' \
                    'Do not retry the identical payload at the same deadline.'
            }
          else
            {
              scenario: :construction,
              error: "#{tool} timeout: reconstruct payload to same goal before raising timeout",
              hint: "Scenario 1 (try first): the #{tool} ruby/command was constructed " \
                    'improperly. Generate it differently to achieve the same goal. ' \
                    'Do not first raise timeout. Record this so it does not recur.'
            }
          end
        end

        public_class_method def self.timeout_result(opts = {})
          return { stdout: '', stderr: '', exit: nil, error: 'timeout', scenario: :construction, hint: '', shell: shell_name } unless opts.is_a?(Hash)

          lesson = timeout_lesson(
            tool: opts[:tool],
            payload: opts[:payload],
            timeout: opts[:timeout]
          )
          {
            stdout: opts[:stdout].to_s,
            stderr: opts[:stderr].to_s,
            exit: nil,
            error: "timeout after #{opts[:timeout].to_i}s",
            scenario: lesson[:scenario],
            hint: lesson[:hint],
            shell: opts[:shell] || shell_name
          }
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
