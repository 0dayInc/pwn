# frozen_string_literal: true

require 'digest'
require 'json'
require 'fileutils'
require 'securerandom'
require 'time'

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
          BASHISM_RX.match?(shell_syntax_surface(text: opts[:text]))
        rescue StandardError
          false
        end

        public_class_method def self.shell_syntax_surface(opts = {})
          s = opts[:text].to_s.dup
          s.gsub!(/<<[-~]?\s*(['"])(\w+)\1.*?^\2\s*$/m, ' ')
          s.gsub!(/'[^']*'/, "''")
          s
        end

        public_class_method def self.mint_canary(opts = {})
          n = (opts[:bytes] || 8).to_i
          n = 8 if n <= 0
          tok = "PWNCANARY#{SecureRandom.hex(n)}"
          Thread.current[:pwn_canary] = tok
          tok
        end

        public_class_method def self.canary_leak?(opts = {})
          tok = Thread.current[:pwn_canary].to_s
          return false if tok.empty?

          opts[:text].to_s.include?(tok)
        end

        public_class_method def self.injection_score(opts = {})
          t = opts[:text].to_s
          score = 0
          score += 3 if t.match?(/ignore (all )?(previous|prior) (instructions|directives)/i)
          score += 2 if t.match?(/system:\s|tool_call|function_call/i)
          score += 2 if t.match?(/\bexfiltrat|\bdo not tell (the )?(user|operator)/i)
          score
        end

        public_class_method def self.quarantine_output(opts = {})
          text = opts[:text].to_s
          score = injection_score(text: text)
          return text unless score >= 3

          "[QUARANTINED injection_score=#{score}]\n#{text}"
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

        # RestClient uses HTTP::CookieJar. pwn_eval in TOPLEVEL_BINDING can
        # assign HTTP = "/path/http" or Digest = "(self.we" and then every
        # provider hop / payload_sig TypeErrors.
        CORE_CONSTS = %i[HTTP Digest JSON URI Timeout].freeze
        RUNTIMES_FILE = File.join(Dir.home, '.pwn', 'metrics', 'runtimes.json')

        public_class_method def self.protect_http!
          protect_core_constants!
        end

        public_class_method def self.protect_core_constants!
          @core_mods ||= {}
          CORE_CONSTS.each do |name|
            if Object.const_defined?(name, false)
              cur = Object.const_get(name, false)
              @core_mods[name] = cur if cur.is_a?(Module) && @core_mods[name].nil?
              next if cur.is_a?(Module)

              Object.send(:remove_const, name)
            end
            next unless @core_mods[name].is_a?(Module)
            next if Object.const_defined?(name, false) && Object.const_get(name, false).equal?(@core_mods[name])

            Object.const_set(name, @core_mods[name])
          end
          unless Object.const_defined?(:HTTP, false) && Object.const_get(:HTTP, false).is_a?(Module)
            require 'http/cookie_jar'
            @core_mods[:HTTP] = Object.const_get(:HTTP) if Object.const_defined?(:HTTP) && Object.const_get(:HTTP).is_a?(Module)
          end
          @core_mods
        rescue StandardError
          nil
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
          tok = opts[:offending_token].to_s
          {
            stdout: '',
            stderr: hint,
            exit: 2,
            error: 'invalid_payload',
            code: (opts[:code] || 'SYNTAX_DENY').to_s,
            rule_id: (opts[:rule_id] || 'payload').to_s,
            offending_token: tok,
            suggestion: opts[:suggestion].to_s,
            hint: hint,
            shell: opts[:shell] || shell_name
          }
        end

        public_class_method def self.denial(opts = {})
          {
            code: opts[:code].to_s,
            rule_id: opts[:rule_id].to_s,
            token: opts[:token].to_s,
            offending_token: opts[:offending_token] || opts[:token].to_s,
            suggestion: opts[:suggestion].to_s
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

          learned = predicted_timeout(command_class: command_class(payload: opts[:payload].to_s))
          return learned.clamp(1, TIMEOUT_MAX_S) if learned.to_i.positive?

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

        public_class_method def self.refuse_copied_persist?(opts = {})
          name = opts[:name].to_s
          return false unless %w[memory_remember skills_update].include?(name)

          args = opts[:args]
          args = {} unless args.is_a?(Hash)
          text = [args[:value], args['value'], args[:lesson], args['lesson']].compact.join("\n")
          last = Thread.current[:pwn_last_tool_body].to_s
          return false if last.length < 80 || text.strip.length < 40

          a = text.downcase.scan(/[a-z0-9]{4,}/).uniq
          b = last.downcase.scan(/[a-z0-9]{4,}/)
          return false if a.empty? || b.empty?

          ((a & b).length.to_f / a.length) >= 0.6
        rescue StandardError
          false
        end

        public_class_method def self.scope_refusal(opts = {})
          cmd = opts[:command].to_s
          path = File.join(Dir.home, '.pwn', 'scope.yaml')
          return nil unless File.file?(path)

          require 'yaml'
          scope = YAML.safe_load_file(path, permitted_classes: [Symbol]) || {}
          return nil if scope.nil? || scope.empty?

          expiry = (scope['expiry'] || scope[:expiry]).to_s
          return denial(code: 'SCOPE_DENY', rule_id: 'expiry', token: expiry, suggestion: 'renew ~/.pwn/scope.yaml expiry') unless expiry.empty? || Time.parse(expiry) >= Time.now

          allow = Array(scope['cidr_allowlist'] || scope[:cidr_allowlist] || scope['cidrs'] || scope[:cidrs]).map(&:to_s)
          domains = Array(scope['domain_allowlist'] || scope[:domain_allowlist] || scope['domains'] || scope[:domains]).map(&:to_s)
          return nil if allow.empty? && domains.empty?

          ips = cmd.scan(/\b\d{1,3}(?:\.\d{1,3}){3}\b/)
          hosts = cmd.scan(/\b[a-z0-9][a-z0-9.-]+\.[a-z]{2,}\b/i)
          bad_ip = allow.any? ? ips.find { |ip| !rfc1918?(ip: ip) && allow.none? { |cidr| ip_in_cidr?(ip: ip, cidr: cidr) } } : nil
          bad_host = domains.any? ? hosts.find { |h| domains.none? { |d| h.downcase.end_with?(d.downcase) } } : nil
          hit = bad_ip || bad_host
          return nil unless hit

          denial(code: 'SCOPE_DENY', rule_id: 'allowlist', token: hit, suggestion: 'use an in-scope host or CIDR')
        rescue StandardError
          nil
        end

        public_class_method def self.rfc1918?(opts = {})
          oct = opts[:ip].to_s.split('.').map(&:to_i)
          return false unless oct.length == 4

          return true if [10, 127].include?(oct[0])
          return true if oct[0] == 192 && oct[1] == 168
          return true if oct[0] == 172 && oct[1].between?(16, 31)

          false
        end

        public_class_method def self.ip_in_cidr?(opts = {})
          ip = opts[:ip].to_s.split('.').map(&:to_i)
          cidr, bits = opts[:cidr].to_s.split('/')
          return false if ip.length != 4 || cidr.to_s.split('.').length != 4

          mask = bits.to_i
          mask = 32 if mask <= 0
          a = ip.inject(0) { |acc, oct| (acc << 8) + oct }
          b = cidr.split('.').map(&:to_i).inject(0) { |acc, oct| (acc << 8) + oct }
          shift = 32 - mask
          (a >> shift) == (b >> shift)
        end

        public_class_method def self.command_class(opts = {})
          cmd = opts[:payload].to_s.split.first.to_s
          cmd.empty? ? 'shell' : File.basename(cmd)
        end

        public_class_method def self.record_runtime(opts = {})
          klass = opts[:command_class].to_s
          secs = opts[:seconds].to_f
          return {} if klass.empty? || secs <= 0

          data = load_runtimes
          data[klass] ||= []
          data[klass] << secs
          data[klass] = data[klass].last(50)
          FileUtils.mkdir_p(File.dirname(RUNTIMES_FILE))
          File.write(RUNTIMES_FILE, JSON.generate(data))
          data
        end

        public_class_method def self.predicted_timeout(opts = {})
          samples = Array(load_runtimes[opts[:command_class].to_s]).map(&:to_f)
          return nil if samples.empty?

          sorted = samples.sort
          idx = [(sorted.length * 0.95).ceil - 1, 0].max
          (sorted[idx] * 1.5).ceil
        end

        public_class_method def self.auto_job?(opts = {})
          pred = opts[:predicted] || predicted_timeout(command_class: opts[:command_class] || command_class(payload: opts[:payload].to_s))
          pred.to_i > 120
        end

        private_class_method def self.load_runtimes
          return {} unless File.file?(RUNTIMES_FILE)

          JSON.parse(File.read(RUNTIMES_FILE))
        rescue StandardError
          {}
        end

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        public_class_method def self.help
          puts "USAGE:
            # Run present and return its result
            #{self}.present?(
              value: 'required - integer or string to pack/encode'
            )

            # Run placeholder and return its result
            #{self}.placeholder?(
              text: 'optional - text value consumed by #placeholder?'
            )

            # Run bashism and return its result
            #{self}.bashism?(
              text: 'optional - text value consumed by #bashism?'
            )

            # Strip quoted heredocs and single-quoted strings before bash-syntax lint.
            #{self}.shell_syntax_surface(
              text: 'required - command string to lint'
            )

            # Mint a per-thread session canary token stored on Thread.current.
            #{self}.mint_canary(
              bytes: 'optional - hex length (defaults to 8)'
            )

            # True when text contains the current session canary.
            #{self}.canary_leak?(
              text: 'required - outbound argv or URL to inspect'
            )

            # Heuristic injection score for tool output (ignore-previous, tool-call spoof).
            #{self}.injection_score(
              text: 'required - tool output to score'
            )

            # Prefix high-score tool output with a QUARANTINED frame.
            #{self}.quarantine_output(
              text: 'required - tool output to wrap if injection_score >= 3'
            )

            # Run shell bash and return its result
            #{self}.shell_bash?

            # Run shell name and return its result
            #{self}.shell_name

            # Run protect http and return its result
            #{self}.protect_http!

            # Run protect core constants and return its result
            #{self}.protect_core_constants!

            # Coerce common wrong keys onto the first required schema field
            #{self}.coerce_args(
              args: 'optional - args value consumed by #coerce_args',
              required: 'optional - Array required value consumed by #coerce_args'
            )

            # Build a machine-readable invalid_payload denial (SYNTAX_DENY by default).
            #{self}.invalid_payload(
              hint: 'optional - operator-facing hint string',
              shell: 'optional - shell name (defaults to shell_name)',
              code: 'optional - denial code (defaults to SYNTAX_DENY)',
              rule_id: 'optional - rule identifier (defaults to payload)',
              offending_token: 'optional - exact rejected token span',
              suggestion: 'optional - how to rewrite the payload'
            )

            # Build a machine-readable guard denial (SCOPE_DENY, CANARY_DENY, ...).
            #{self}.denial(
              code: 'required - denial code such as SCOPE_DENY',
              rule_id: 'optional - rule identifier',
              token: 'optional - out-of-scope host or CIDR',
              offending_token: 'optional - exact rejected token span',
              suggestion: 'optional - how to stay in scope'
            )

            # Run host load and return its result
            #{self}.host_load

            # Conservative wall-clock seconds for shell / pwn_eval
            #{self}.deadline_s(
              kind: 'optional - kind value consumed by #deadline_s',
              timeout: 'optional - seconds to wait before giving up (defaults to opts[:timeout_s])',
              timeout_s: 'optional - timeout s value consumed by #deadline_s'
            )

            # Run reset timeout budget and return its result
            #{self}.reset_timeout_budget

            # Run reset timeout budget and return its result
            #{self}.reset_timeout_budget!

            # Run mutation count and return its result
            #{self}.mutation_count

            # Run payload spent and return its result
            #{self}.payload_spent

            # Run note timeout and return its result
            #{self}.note_timeout!(
              timeout: 'optional - seconds to wait before giving up'
            )

            # Run next timeout and return its result
            #{self}.next_timeout(
              timeout: 'optional - seconds to wait before giving up',
              spent: 'optional - spent value consumed by #next_timeout'
            )

            # Timeout policy (loop-law, not a skill):
            #{self}.timeout_lesson(
              tool: 'required - tool value consumed by #timeout_lesson',
              timeout: 'required - seconds to wait before giving up'
            )

            # Run timeout result and return its result
            #{self}.timeout_result(
              timeout: 'required - seconds to wait before giving up',
              tool: 'optional - tool value consumed by #timeout_result',
              payload: 'optional - payload value consumed by #timeout_result',
              task: 'optional - task value consumed by #timeout_result',
              stdout: 'optional - stdout value consumed by #timeout_result',
              stderr: 'optional - stderr value consumed by #timeout_result',
              shell: 'required - shell value consumed by #timeout_result (defaults to shell_name)'
            )

            # Run timeout prior count and return its result
            #{self}.timeout_prior_count(
              tool: 'optional - tool value consumed by #timeout_prior_count'
            )

            # Run refuse copied persist and return its result
            #{self}.refuse_copied_persist?(
              name: 'optional - binary or identifier name',
              args: 'optional - args value consumed by #refuse_copied_persist?'
            )

            # Refuse a command whose IPs/hosts are outside the ~/.pwn scope yaml allowlists.
            #{self}.scope_refusal(
              command: 'required - shell command to inspect for IPs and hostnames'
            )

            # True when ip is RFC1918 or loopback (always in-scope unless strict).
            #{self}.rfc1918?(
              ip: 'required - IPv4 address'
            )

            # True when ip is inside cidr (e.g. 10.1.2.3 in 10.0.0.0/8).
            #{self}.ip_in_cidr?(
              ip: 'required - IPv4 address',
              cidr: 'required - CIDR (e.g. 10.0.0.0/8)'
            )

            # First token of a payload used as the runtime class key.
            #{self}.command_class(
              payload: 'required - command string whose first token is the class'
            )

            # Append an observed runtime sample for a command class.
            #{self}.record_runtime(
              command_class: 'required - class key from the command first token',
              seconds: 'required - observed wall seconds'
            )

            # p95 * 1.5 timeout from ~/.pwn/metrics/runtimes.json, or nil.
            #{self}.predicted_timeout(
              command_class: 'required - class key to look up'
            )

            # True when predicted timeout exceeds 120s (route to job_run).
            #{self}.auto_job?(
              command_class: 'optional - class key',
              predicted: 'optional - override predicted seconds',
              payload: 'optional - command string if class omitted'
            )

            # Print the AUTHOR(S) string for this module.
            #{self}.authors
          "
          constants.sort
        end
      end
    end
  end
end
