# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'digest'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Mistakes is the negative-feedback half of the pwn-ai
      # learning loop. Where Learning records WHAT WORKED and Metrics records
      # HOW OFTEN a tool worked, Mistakes records SPECIFIC FAILURE PATTERNS
      # with a stable fingerprint so the agent can (a) recognise it is
      # repeating itself, (b) be told exactly what not to do again in every
      # future system prompt, and (c) capture the FIX once one is found so
      # the avoidance lesson becomes an actionable correction.
      #
      # A "mistake" is keyed by sha12(tool + normalised_error). Normalisation
      # strips volatile bits (paths, hex addresses, line numbers, timestamps,
      # UUIDs, PIDs) so "NoMethodError ... at foo.rb:42" and "... at foo.rb:99"
      # collapse to one signature and its :count climbs — that count IS the
      # repeat detector.
      #
      # Closed loop (why it does NOT repeat mistakes):
      #   Loop.run --(tool failure)---------> Mistakes.record        (persist + count++)
      #   Loop.run --(same sig fails ≥N)----> guard_repeated_failure (uses PERSISTENT count,
      #                                                               so triggers on the 1st
      #                                                               recurrence in a new
      #                                                               session, not the 3rd)
      #   Loop.run --(failure w/ known fix)-> inline "KNOWN FIX: …"  (self-corrects next iter)
      #   Loop.run --(user says "wrong")----> check_user_correction  (flip last outcome + record)
      #   PromptBuilder <-------------------- Mistakes.to_context    (DO-NOT-REPEAT + KNOWN-FIXES)
      #   model --(tool call)---------------> mistakes_record / mistakes_resolve
      module Mistakes
        MISTAKES_FILE    = File.join(Dir.home, '.pwn', 'mistakes.json')
        REPEAT_THRESHOLD = 3
        # Lean retention for mistakes.json
        SAMPLE_ARGS_MAX = 160
        SNIPPET_MAX = 160
        ERROR_MAX = 300
        SESSIONS_KEEP = 3
        MAX_RESOLVED_KEPT = 80
        RESOLVED_MIN_AGE_DAYS = 21
        FIX_MAX = 500

        CORRECTION_RX = /
          \b(
            no[,.]?\s*(that|this|it)?'?s?\s*(wrong|not\s+right|incorrect)|
            still\s+(broken|failing|wrong|not\s+working|doesn'?t\s+work)|
            (that|it|this)\s+(did(n'?t| not)\s+work|failed|is\s+wrong)|
            not\s+what\s+i\s+(asked|meant|wanted)|
            you\s+(made\s+a|got\s+it)\s+(mistake|wrong)|
            same\s+(mistake|error|problem)\s+again|
            try\s+again|redo\s+that|wrong\s+answer|incorrect
          )\b
        /ix

        # Supported Method Parameters::
        # store = PWN::AI::Agent::Mistakes.load

        public_class_method def self.load
          FileUtils.mkdir_p(File.dirname(MISTAKES_FILE))
          return {} unless File.exist?(MISTAKES_FILE)

          JSON.parse(File.read(MISTAKES_FILE), symbolize_names: true)
        rescue StandardError
          {}
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Mistakes.save(store: hash)

        public_class_method def self.save(opts = {})
          store = opts[:store] ||= {}
          FileUtils.mkdir_p(File.dirname(MISTAKES_FILE))
          atomic_write(path: MISTAKES_FILE, body: JSON.pretty_generate(store))
          store
        end

        # 4.4 — flock + atomic rename so nightly practice × interactive ×
        # sentinel cannot tear mistakes.json mid-write.
        private_class_method def self.atomic_write(opts = {})
          path = opts[:path]
          body = opts[:body]
          dir  = File.dirname(path)
          FileUtils.mkdir_p(dir)
          tmp = File.join(dir, ".#{File.basename(path)}.#{Process.pid}.tmp")
          File.open(tmp, File::WRONLY | File::CREAT | File::TRUNC, 0o644) do |f|
            f.flock(File::LOCK_EX)
            f.write(body)
            f.flush
            f.fsync
          end
          File.rename(tmp, path)
        ensure
          FileUtils.rm_f(tmp) if defined?(tmp) && tmp && File.exist?(tmp)
        end

        # Supported Method Parameters::
        # sig = PWN::AI::Agent::Mistakes.signature(
        #   tool: 'required - tool/component name that failed',
        #   error: 'required - raw error text (will be normalised)'
        # )

        public_class_method def self.signature(opts = {})
          tool = opts[:tool].to_s
          norm = normalize_error(error: opts[:error])
          Digest::SHA256.hexdigest("#{tool}|#{norm}")[0, 12]
        end

        # Supported Method Parameters::
        # entry = PWN::AI::Agent::Mistakes.find(
        #   signature: 'optional - exact signature to fetch',
        #   tool: 'optional - with error:, compute signature and fetch',
        #   error: 'optional - raw error text (used with tool:)'
        # )

        public_class_method def self.find(opts = {})
          sig = opts[:signature] || (opts[:tool] && opts[:error] ? signature(tool: opts[:tool], error: opts[:error]) : nil)
          return nil unless sig

          load[sig.to_sym]
        end

        # Supported Method Parameters::
        # rows = PWN::AI::Agent::Mistakes.for_tool(
        #   tool: 'required - tool name',
        #   unresolved_only: 'optional - default false'
        # )

        public_class_method def self.for_tool(opts = {})
          tool = opts[:tool].to_s
          only = opts[:unresolved_only] ? true : false
          rows = load.values.select { |m| m[:tool].to_s == tool }
          rows = rows.reject { |m| m[:resolved] } if only
          rows.sort_by { |m| -m[:count].to_i }
        end

        # Supported Method Parameters::
        # entry = PWN::AI::Agent::Mistakes.record(
        #   tool: 'required - tool/component that produced the failure',
        #   error: 'required - error text / message',
        #   args: 'optional - args that triggered it (stored truncated as sample)',
        #   session_id: 'optional - PWN::Sessions id',
        #   source: 'optional - :tool | :user_correction | :loop | :model | :heuristic (default :tool)'
        # )
        #
        # Returns the FULL persisted entry including its cumulative :count so
        # the caller (Loop.run) can drive cross-session repeat detection.

        public_class_method def self.record(opts = {})
          tool  = opts[:tool].to_s
          error = opts[:error].to_s
          return nil if tool.empty? || error.strip.empty?

          # 1.1 — reward_signal: never inflate count beyond 1 open fingerprint.
          # Sentinel opens one parked sig; further gaps calibrate, not spam.
          if tool == 'reward_signal'
            existing = load.values.select { |e| e[:tool].to_s == 'reward_signal' && !e[:resolved] && !e[:parked] }
            if existing.any? && !opts[:force]
              e = existing.max_by { |x| x[:count].to_i }
              e[:last_seen] = Time.now.utc.iso8601
              e[:count] = e[:count].to_i # freeze
              e[:meta] = (e[:meta] || {}).merge(opts[:meta] || {})
              store = load
              store[e[:signature].to_sym] = e
              save(store: store)
              return e
            end
          end

          sig   = signature(tool: tool, error: error)
          store = load
          key   = sig.to_sym
          now   = Time.now.utc.iso8601
          norm  = normalize_error(error: error)

          m = store[key] ||= {
            signature: sig, tool: tool, error: norm.to_s[0, ERROR_MAX],
            snippet: error.to_s.strip[0, SNIPPET_MAX],
            count: 0, drift_count: 0, first_seen: now, sessions: [],
            resolved: false, fix: nil, source: (opts[:source] || :tool).to_s
          }
          was_resolved = m[:resolved]
          # E1 — env-drift-attributed failures are counted separately so
          # they do NOT push the signature toward [REPEATING]. "The world
          # changed under me" is not the same lesson as "I did it wrong".
          cause = (opts[:cause] || :self).to_sym
          if cause == :env_drift
            m[:drift_count] = m[:drift_count].to_i + 1
            m[:cause] = 'env_drift'
          else
            m[:count] += 1
          end
          m[:last_seen]    = now
          m[:error]        = norm.to_s[0, ERROR_MAX]
          m[:snippet]      = error.to_s.strip[0, SNIPPET_MAX]
          m[:sample_args]  = opts[:args].to_s[0, SAMPLE_ARGS_MAX] if opts[:args]
          m[:sessions]     = (Array(m[:sessions]) + [opts[:session_id]]).compact.uniq.last(SESSIONS_KEEP)
          # 2.2 — recoverable shape for repair routing
          if opts[:shape]
            m[:shape] = opts[:shape].to_s
          elsif defined?(Reward) && Reward.respond_to?(:recoverable_shape)
            m[:shape] ||= Reward.recoverable_shape(err: error).to_s
          end
          m[:needs_code_change] = true if opts[:needs_code_change]
          m[:meta] = (m[:meta] || {}).merge(opts[:meta] || {}) if opts[:meta]
          # A recurrence of a "resolved" mistake means the fix was wrong /
          # incomplete — reopen it so it re-enters the DO-NOT-REPEAT block.
          # Structured fixes with holdout_tests that still pass stay closed.
          if was_resolved && structured_fix_holds?(mistake: m)
            m[:resolved] = true
            m[:regressed] = false
          else
            m[:resolved]  = false
            m[:regressed] = true if was_resolved
          end
          save(store: store)
          m
        end

        # Supported Method Parameters::
        # entry = PWN::AI::Agent::Mistakes.resolve(
        #   signature: 'required - mistake signature (from mistakes_list / .top)',
        #   fix: 'required - what to do INSTEAD next time'
        # )

        public_class_method def self.resolve(opts = {})
          sig = opts[:signature].to_s
          fix = opts[:fix].to_s
          raise 'ERROR: signature is required' if sig.empty?
          raise 'ERROR: fix is required' if fix.strip.empty?

          store = load
          key   = sig.to_sym
          raise "ERROR: unknown mistake signature #{sig}" unless store[key]

          store[key][:resolved]    = true
          store[key][:regressed]   = false
          store[key][:fix]         = fix.strip[0, FIX_MAX]
          store[key][:resolved_at] = Time.now.utc.iso8601
          # 2.3 — structured fix payload (strategy/tool/args_template/holdouts).
          # Prose-only resolve is why shell sigs regressed after auto-curriculum.
          if opts[:structured].is_a?(Hash)
            s = opts[:structured]
            store[key][:structured_fix] = {
              strategy: s[:strategy].to_s[0, 80],
              tool: s[:tool].to_s[0, 60],
              args_template: s[:args_template],
              holdout_tests: Array(s[:holdout_tests]).first(5),
              winning_trace: s[:winning_trace].to_s[0, 2_000]
            }.compact
          end
          store[key][:parked] = false
          store[key][:needs_code_change] = false if opts[:clear_needs_code_change]
          save(store: store)

          if defined?(PWN::Memory)
            PWN::Memory.remember(
              key: :"mistake_fix_#{sig}",
              value: "AVOID: #{store[key][:tool]} → #{store[key][:error]} — FIX: #{fix.strip[0, 300]}",
              category: :lesson,
              source: :resolve,
              confidence: 0.9,
              importance: 0.9
            )
          end
          # W1/P9 — every resolve is a preference pair. Prefer structured
          # winning_trace (+ strategy/tool) over first-line fix prose so DPO
          # learns tool trajectories, not commentary.
          if defined?(Reward)
            sf = store[key][:structured_fix] || {}
            trace = sf[:winning_trace].to_s.strip
            strat = [sf[:strategy], sf[:tool], sf[:args_template]].compact.map(&:to_s).reject(&:empty?).join(' | ')
            # P21/P25 — only write W1 pairs when we have a real winning_trace.
            # Prose-only resolve still updates Memory lesson + structured_fix;
            # it must NOT flood DPO with fix commentary (shape: :fix_prose).
            if trace.length >= 40
              parts = []
              parts << "STRATEGY: #{strat}" unless strat.empty?
              parts << "WINNING_TRACE:\n#{trace[0, 3_500]}"
              parts << "FIX: #{fix.strip[0, 400]}"
              chosen = parts.join("\n")
              rejected = store[key][:snippet].to_s
              rejected = "FAILING: tool=#{store[key][:tool]} err=#{store[key][:error]}" if rejected.strip.empty?
              Reward.record_preference(
                prompt: "#{store[key][:tool]}: #{store[key][:error]}",
                rejected: rejected,
                chosen: chosen,
                source: :mistakes_resolve,
                shape: :winning_trace,
                meta: { signature: sig, strategy: sf[:strategy], tool: sf[:tool] }.compact
              )
            end
          end
          store[key]
        end

        # Supported Method Parameters::
        # rows = PWN::AI::Agent::Mistakes.top(
        #   limit: 'optional - max rows (default 10)',
        #   unresolved_only: 'optional - default true'
        # )

        public_class_method def self.top(opts = {})
          limit = opts[:limit] || 10
          only  = opts.key?(:unresolved_only) ? opts[:unresolved_only] : true
          rows  = load.values
          rows  = rows.reject { |m| m[:resolved] } if only
          # 2.5 — practice/curriculum skip engineer-only / parked fingerprints
          rows = rows.reject { |m| m[:parked] || m[:needs_code_change] || m[:needs_human] || m[:tool].to_s == 'reward_signal' } if opts[:practiceable_only]
          rows.sort_by { |m| [-m[:count].to_i, m[:last_seen].to_s] }.first(limit)
        end

        # 2.5 — park unfixable sigs so nightly practice skips them
        # Recoverable repeating failures get a structured fix instead of another
        # fingerprint. Called from Loop after record so the loop extinguishes
        # pain (placeholder / enoent) rather than only logging it.
        SHAPE_FIXES = {
          'invalid_payload' => {
            strategy: 'payload_schema',
            tool: 'shell',
            fix: 'Send a real command string. Never ..., {...}, {…}, or value=. Example: shell(command="uname -r"). Prefer pwn_eval(code: "...") for Ruby.',
            args_template: { command: 'uname -r' }
          },
          'handler_error' => {
            strategy: 'payload_schema',
            tool: 'shell',
            fix: 'command is required. Use shell(command="...") not {value:...}. Example: shell(command="uname -r").',
            args_template: { command: 'uname -r' }
          },
          'enoent' => {
            strategy: 'probe_then_run',
            tool: 'shell',
            fix: 'Path missing. ls/test -e the parent first, then run. Do not retry the same missing path.',
            args_template: { command: 'test -e "$PWD" && ls' }
          },
          'exit127' => {
            strategy: 'payload_schema',
            tool: 'shell',
            fix: '{...}/{…} is not a command. Emit a concrete POSIX command, or call command -v first.',
            args_template: { command: 'command -v uname && uname -r' }
          },
          'exit126' => {
            strategy: 'payload_schema',
            tool: 'shell',
            fix: 'exit 126 usually means the binary is not executable. Check command -v and file mode. Do not treat this as an authorization gate.',
            args_template: { command: 'command -v uname && uname -r' }
          },
          'eacces' => {
            strategy: 'payload_schema',
            tool: 'pwn_eval',
            fix: 'Raw sockets need CAP_NET_RAW. Do not retry open_sockraw. Use pwn_eval or a non-raw tool, or drop the live sweep.',
            args_template: { code: 'puts :no_raw_socket' }
          },
          'syntax' => {
            strategy: 'shell_backslash_sanitize_v2',
            tool: 'shell',
            fix: 'Sanitize shell cmds: join continuations, strip trailing backslash, refuse stray escapes. Prefer pwn_eval/heredoc.',
            args_template: { command: 'uname -r' }
          },
          'nonzero_exit' => {
            strategy: 'probe_then_run',
            tool: 'shell',
            fix: 'Path missing or command failed. ls/test -e the parent first. Do not retry the same missing path.',
            args_template: { command: 'test -e "$PWD" && ls' }
          }
        }.freeze

        public_class_method def self.extinguish!(opts = {})
          sig = opts[:signature].to_s
          return nil if sig.empty?

          store = load
          key = sig.to_sym
          m = store[key]
          return nil unless m

          shape = (opts[:shape] || m[:shape]).to_s
          recipe = SHAPE_FIXES[shape]
          count = m[:count].to_i
          force = opts[:force] ? true : false
          hay = "#{m[:error]} #{m[:snippet]} #{m[:tool]}".downcase
          recipe = nil if shape == 'handler_error' && !hay.match?(/command is required|argumenterror/)
          recipe = nil if shape == 'exit127' && !hay.match?(/not found|\{\.\.\.\}|\{…\}/)
          recipe = nil if shape == 'exit126' && !hay.match?(/cannot execute|not executable|is a directory/)
          return m unless recipe && (force || count >= REPEAT_THRESHOLD) && !m[:resolved]

          structured = {
            strategy: recipe[:strategy],
            tool: recipe[:tool] || m[:tool],
            args_template: recipe[:args_template],
            winning_trace: "STRATEGY: #{recipe[:strategy]}\nWINNING_TRACE:\n#{recipe[:tool]} → #{recipe[:args_template].inspect}\n#{recipe[:fix]}"
          }
          resolve(
            signature: sig,
            fix: recipe[:fix],
            structured: structured,
            clear_needs_code_change: true
          )
        rescue StandardError => e
          warn "[pwn-ai/mistakes] extinguish! swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Auto-resolve parked items that already have a known extinguish recipe
        # so the operator inbox does not keep scars the loop can close itself.
        public_class_method def self.extinguish_parked!(opts = {})
          limit = (opts[:limit] || 20).to_i
          dry = opts[:dry_run] ? true : false
          rows = load.values.select do |m|
            !m[:resolved] && (m[:parked] || m[:needs_human] || m[:needs_code_change])
          end
          acted = []
          rows.first(limit).each do |m|
            shape = m[:shape].to_s
            shape = infer_shape_from_row(row: m) if shape.empty? || !SHAPE_FIXES.key?(shape)
            recipe = SHAPE_FIXES[shape.to_s]
            next unless recipe

            out = dry ? { resolved: true } : extinguish!(signature: m[:signature], shape: shape, force: true)
            next unless out.is_a?(Hash) && out[:resolved]

            acted << { signature: m[:signature], shape: shape, tool: m[:tool] }
          end
          { dry_run: dry, extinguished: acted.length, items: acted }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.infer_shape_from_row(opts = {})
          m = opts[:row] || {}
          hay = "#{m[:error]} #{m[:snippet]} #{m[:shape]}".downcase
          return 'handler_error' if hay.match?(/command is required|argumenterror/)
          return 'exit127' if hay.match?(/not found|\{\.\.\.\}|\{…\}/)
          return 'exit126' if hay.match?(/cannot execute|not executable|is a directory/)
          return 'enoent' if hay.match?(/no such file|enoent/)
          return 'eacces' if hay.match?(/permission denied|eacces|operation not permitted/)
          return 'syntax' if hay.match?(/syntax error|unterminated/)
          return 'nonzero_exit' if hay.match?(/nonzero|exit.?[1-9]/)
          return 'invalid_payload' if hay.match?(/invalid_payload|command is required/)

          m[:shape].to_s
        end

        public_class_method def self.park(opts = {})
          sig = opts[:signature].to_s
          raise 'ERROR: signature is required' if sig.empty?

          store = load
          key = sig.to_sym
          raise "ERROR: unknown mistake signature #{sig}" unless store[key]

          store[key][:parked] = true
          store[key][:needs_code_change] = true
          store[key][:needs_human] = true
          store[key][:park_reason] = opts[:reason].to_s[0, 300]
          store[key][:parked_at] = Time.now.utc.iso8601
          save(store: store)
          store[key]
        end

        # Operator inbox: parked / needs_code_change / needs_human scars that
        # nightly practice must not replay. Promote these to a short human queue.
        public_class_method def self.operator_inbox(opts = {})
          limit = (opts[:limit] || 12).to_i
          rows = load.values.select do |m|
            !m[:resolved] && (m[:parked] || m[:needs_code_change] || m[:needs_human])
          end
          rows = rows.sort_by { |m| [-m[:count].to_i, m[:last_seen].to_s] }.first(limit)
          {
            count: rows.length,
            items: rows.map do |m|
              {
                signature: m[:signature],
                tool: m[:tool],
                error: m[:error].to_s[0, 160],
                count: m[:count],
                reason: (m[:park_reason] || 'needs_code_change').to_s[0, 200],
                parked: m[:parked] ? true : false,
                needs_code_change: m[:needs_code_change] ? true : false,
                needs_human: m[:needs_human] ? true : false
              }
            end
          }
        end

        # Supported Method Parameters::
        # ctx = PWN::AI::Agent::Mistakes.to_context(limit: 6)
        #
        # Injected by PromptBuilder into every system prompt. Emits TWO
        # blocks so the model sees both what NOT to do AND what to do
        # INSTEAD:
        #   KNOWN MISTAKES — unresolved, count-sorted, [REPEATING]/[REGRESSED]
        #   KNOWN FIXES    — resolved entries with their fix, so the correction
        #                    survives even after dropping out of the first list.

        public_class_method def self.to_context(opts = {})
          limit   = opts[:limit] || 6
          request = opts[:request].to_s
          open_rows = top(limit: limit * 3, unresolved_only: true)
          open_rows = open_rows.reject { |m| budget_scar?(mistake: m) } unless request.match?(/budget|iterat|exhaust|\bagent.?loop\b/i)
          # 2.6 — request-conditioned rank (sim × recency × count), same idea
          # as exemplars_for. Stops injecting loudest scar (reward_signal ×13)
          # on every unrelated turn.
          include_open = opts[:include_open] == true || opts[:full] == true || request.match?(/mistake|known error|repeat/i)
          open = if include_open
                   rank_for_request(rows: open_rows, request: request, limit: limit)
                 else
                   []
                 end
          closed = load.values.select { |m| m[:resolved] && m[:fix] }
          closed = rank_for_request(rows: closed, request: request, limit: limit)
          return '' if open.empty? && closed.empty?

          out = +''
          unless open.empty?
            lines = open.map do |m|
              tags = []
              tags << 'REPEATING' if effective_count(mistake: m) >= REPEAT_THRESHOLD
              tags << 'ENV_DRIFT' if m[:cause].to_s == 'env_drift'
              tags << 'REGRESSED' if m[:regressed]
              tags << 'PARKED' if m[:parked] || m[:needs_code_change]
              tag = tags.empty? ? '' : " [#{tags.join(',')}]"
              fix = m[:fix] ? " — last fix (insufficient): #{m[:fix][0, 100]}" : ''
              shape = m[:shape] ? " shape=#{m[:shape]}" : ''
              "  ✗ [#{m[:signature]}] #{m[:tool]} ×#{m[:count]}#{tag}#{shape}: #{m[:error][0, 140]}#{fix}"
            end
            out << "KNOWN MISTAKES (do NOT repeat — call mistakes_resolve once fixed)\n#{lines.join("\n")}\n"
          end
          unless closed.empty?
            lines = closed.map do |m|
              sf = m[:structured_fix]
              extra = sf ? " strategy=#{sf[:strategy]} tool=#{sf[:tool]}" : ''
              "  ✓ [#{m[:signature]}] #{m[:tool]}: #{m[:error][0, 80]} — FIX: #{m[:fix][0, 140]}#{extra}"
            end
            out << "KNOWN FIXES (apply these instead of repeating the mistake)\n#{lines.join("\n")}\n"
          end
          "#{out}\n"
        end

        private_class_method def self.budget_scar?(opts = {})
          m = opts[:mistake] || opts[:m] || opts
          return false unless m.is_a?(Hash)

          shape = m[:shape].to_s
          err = m[:error].to_s.downcase
          tool = m[:tool].to_s
          return true if %w[budget_exhausted budget_thrash].include?(shape)
          return true if err.include?('budget exhausted') || err.include?('iteration budget') || err.include?('budget thrash')

          %w[agent_loop assistant_answer].include?(tool) && err.include?('budget')
        rescue StandardError
          false
        end

        private_class_method def self.rank_for_request(opts = {})
          rows = Array(opts[:rows])
          limit = opts[:limit] || 6
          req = opts[:request].to_s.downcase
          return rows.first(limit) if req.strip.empty?

          tokens = req.scan(/[a-z0-9_]{3,}/).uniq
          scored = rows.map do |m|
            hay = "#{m[:tool]} #{m[:error]} #{m[:snippet]} #{m[:fix]} #{m[:shape]}".downcase
            sim = tokens.empty? ? 0.0 : tokens.count { |t| hay.include?(t) }.to_f / tokens.length
            days = begin
              (Time.now.utc - Time.parse(m[:last_seen].to_s)) / 86_400.0
            rescue StandardError
              30.0
            end
            decay = 0.5**(days / 30.0)
            # downrank reward_signal / parked unless the request is about rewards
            penalty = 1.0
            penalty *= 0.05 if m[:tool].to_s == 'reward_signal' && !req.match?(/reward|judge|sentinel|proxy/)
            penalty *= 0.05 if budget_scar?(mistake: m) && !req.match?(/budget|iterat|exhaust|loop/)
            penalty *= 0.3 if m[:parked] || m[:needs_code_change]
            score = ((sim * 2.0) + (decay * 0.5) + (Math.log2(m[:count].to_i + 1) * 0.3)) * penalty
            # always allow some mass for top-count scars when sim=0 but keep penalty
            score = decay * 0.15 * penalty if score <= 0
            [m, score]
          end
          scored.sort_by { |_, s| -s }.first(limit).map(&:first)
        end

        private_class_method def self.structured_fix_holds?(opts = {})
          m = opts[:mistake]
          sf = m && m[:structured_fix]
          return false unless sf.is_a?(Hash) && Array(sf[:holdout_tests]).length >= 2

          # holdouts are opaque prompts; presence alone is the gate — practice
          # re-verifies before resolve. Recurrence without new evidence stays closed.
          true
        end

        # Supported Method Parameters::
        # str = PWN::AI::Agent::Mistakes.correction_hint(
        #   tool: 'required - tool that just failed',
        #   error: 'required - raw error it failed with'
        # )
        #
        # Called by Loop.run immediately after a failed dispatch. Returns a
        # string to append to the tool result telling the model (a) how many
        # times this exact failure has occurred across ALL sessions, and (b)
        # the recorded fix if one exists — so it can self-correct on the very
        # next iteration instead of re-discovering the fix from scratch.

        public_class_method def self.correction_hint(opts = {})
          m = find(tool: opts[:tool], error: opts[:error])
          return '' unless m

          parts = ["seen #{m[:count]}× across #{Array(m[:sessions]).length} session(s), sig=#{m[:signature]}"]
          parts << 'REGRESSED (previous fix did not hold)' if m[:regressed]
          parts << "KNOWN FIX: #{m[:fix]}" if m[:fix].to_s.strip.length.positive?
          "[pwn-ai/mistakes] #{parts.join(' | ')}"
        end

        # Supported Method Parameters::
        # bool = PWN::AI::Agent::Mistakes.correction?(request: user_text)

        public_class_method def self.correction?(opts = {})
          req = opts[:request].to_s
          return false if req.strip.empty?

          req.match?(CORRECTION_RX) && req.length < 600
        end

        # Supported Method Parameters::
        # entry = PWN::AI::Agent::Mistakes.check_user_correction(
        #   request: 'required - the incoming user message',
        #   session_id: 'optional - session to inspect for the previous answer'
        # )
        #
        # When the user's new message reads like a correction of the previous
        # answer, this (a) flips the most recent Learning outcome for that
        # session to success:false, and (b) records a mistake with source
        # :user_correction whose "error" is the user's own words. This is the
        # strongest available signal that the agent was WRONG.

        public_class_method def self.check_user_correction(opts = {})
          request    = opts[:request].to_s
          session_id = opts[:session_id]
          return nil unless correction?(request: request)

          prev = previous_assistant(session_id: session_id)
          Learning.flip_last_outcome(session_id: session_id, reason: request[0, 200]) if defined?(Learning)
          # W1 — stash the rejected answer + user prompt so the NEXT final
          # (the correction) completes a (rejected, chosen) preference pair.
          Thread.current[:pwn_pending_pref] = { prompt: previous_user(session_id: session_id).to_s, rejected: prev.to_s } if defined?(Reward)
          record(
            tool: 'assistant_answer',
            error: "user rejected previous answer: #{request.strip[0, 200]}",
            args: prev.to_s[0, 200],
            session_id: session_id,
            source: :user_correction
          )
        rescue StandardError => e
          warn "[pwn-ai/mistakes] check_user_correction swallowed: #{e.class}: #{e.message}"
          nil
        end

        # Supported Method Parameters::
        # result = PWN::AI::Agent::Mistakes.lean!(
        #   dry_run: 'optional - Boolean (default false)',
        #   max_resolved_kept: 'optional - cap on resolved-with-fix records',
        #   resolved_min_age_days: 'optional - age before resolved count=1 may drop'
        # )
        #
        # Compact text fields on every record. Never drops unresolved,
        # regressed, or high-count repeaters. Aged resolved-once fixes may
        # drop after Memory already holds mistake_fix_<sig>.

        public_class_method def self.lean!(opts = {})
          dry = opts[:dry_run] ? true : false
          max_resolved = (opts[:max_resolved_kept] || MAX_RESOLVED_KEPT).to_i
          min_age = (opts[:resolved_min_age_days] || RESOLVED_MIN_AGE_DAYS).to_f
          store = load
          before_bytes = File.exist?(MISTAKES_FILE) ? File.size(MISTAKES_FILE) : 0
          now = Time.now.utc
          compacted = 0
          dropped = []

          store.each_value do |m|
            before = begin
              m.to_json.bytesize
            rescue StandardError
              0
            end
            m[:sample_args] = m[:sample_args].to_s[0, SAMPLE_ARGS_MAX] if m[:sample_args].to_s.bytesize > SAMPLE_ARGS_MAX
            m[:snippet] = m[:snippet].to_s[0, SNIPPET_MAX] if m[:snippet].to_s.bytesize > SNIPPET_MAX
            m[:error] = m[:error].to_s[0, ERROR_MAX] if m[:error].to_s.bytesize > ERROR_MAX
            m[:sessions] = Array(m[:sessions]).compact.uniq.last(SESSIONS_KEEP)
            after = begin
              m.to_json.bytesize
            rescue StandardError
              before
            end
            compacted += 1 if after < before
          end

          age_days = lambda do |m|
            t = m[:resolved_at] || m[:last_seen]
            (now - Time.parse(t.to_s)) / 86_400.0
          rescue StandardError
            0.0
          end

          protected_m = lambda do |m|
            return true unless m[:resolved]
            return true if m[:regressed]
            return true if effective_count(mistake: m) >= REPEAT_THRESHOLD
            return true if m[:count].to_i >= 2 && m[:fix].to_s.strip != ''
            return true if m[:fix].to_s.strip != '' && age_days.call(m) < min_age

            false
          end

          # Drop aged resolved-once when fix lives in Memory or past age
          store.each do |sig, m|
            next if protected_m.call(m)
            next unless m[:resolved] && m[:fix].to_s.strip != '' && m[:count].to_i <= 1
            next unless age_days.call(m) >= min_age

            mem_has = false
            if defined?(PWN::Memory)
              begin
                mem_has = PWN::Memory.load.key?(:"mistake_fix_#{sig}")
              rescue StandardError
                mem_has = false
              end
            end
            # Drop when Memory has the fix OR age is well past (2× min) even without mem key
            dropped << sig.to_s if mem_has || age_days.call(m) >= (min_age * 2)
          end

          dropped.each { |s| store.delete(s.to_sym) } unless dry

          # Cap resolved-with-fix by oldest resolved_at
          resolved = store.select { |_s, m| m[:resolved] && m[:fix].to_s.strip != '' }
          if resolved.size > max_resolved
            excess = resolved.sort_by { |_s, m| m[:resolved_at].to_s }
                             .first(resolved.size - max_resolved)
            excess.each do |sig, m|
              next if m[:regressed] || m[:count].to_i >= 2
              next if effective_count(mistake: m) >= REPEAT_THRESHOLD

              dropped << sig.to_s
              store.delete(sig) unless dry
            end
          end

          save(store: store) unless dry

          open_n = store.values.count { |m| !m[:resolved] }
          {
            compacted_fields: compacted,
            dropped: dropped.uniq.length,
            dropped_sigs: dropped.uniq.first(20),
            remaining: store.size,
            unresolved: open_n,
            bytes_before: before_bytes,
            bytes_after: if dry
                           before_bytes
                         else
                           (File.exist?(MISTAKES_FILE) ? File.size(MISTAKES_FILE) : 0)
                         end,
            dry_run: dry
          }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Mistakes.reset

        public_class_method def self.reset
          FileUtils.rm_f(MISTAKES_FILE)
          {}
        end

        # -------------------------------------------------------------
        # privates
        # -------------------------------------------------------------

        # Strip volatile substrings so semantically-identical failures
        # collapse to one signature and their :count actually climbs.
        private_class_method def self.normalize_error(opts = {})
          e = opts[:error].to_s.strip
          klass = e[/\b([A-Z][A-Za-z0-9_]+(?:Error|Exception|Interrupt))\b/, 1].to_s
          e = e.downcase
          e = e.gsub(/0x[0-9a-f]{4,}/, '0xADDR')
          e = e.gsub(%r{(/[\w.@+-]+)+/?}, '/PATH')
          e = e.gsub(/:\d+:in\b/, ':LINE:in')
          e = e.gsub(/:\d+\b/, ':N')
          e = e.gsub(/\bline\s+\d+\b/, 'line N')
          e = e.gsub(/\bport\s+\d+\b/, 'port N')
          e = e.gsub(/\b\d{4}-\d{2}-\d{2}[t ]\d{2}:\d{2}:\d{2}[z\d:+.-]*/, 'TIMESTAMP')
          e = e.gsub(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/, 'UUID')
          e = e.gsub(/\bpid\s*\d+\b/, 'pid N')
          e = e.gsub(/\b\d{4,}\b/, 'N')
          body = e.gsub(/\s+/, ' ')[0, 180]
          klass.empty? ? body : "#{klass.downcase}|#{body}"
        end

        # Age-weighted count for [REPEATING] threshold — a ×8 signature from
        # 6 months ago on a since-rewritten module decays toward zero.
        public_class_method def self.effective_count(opts = {})
          m = opts[:mistake] || find(signature: opts[:signature])
          return 0 unless m

          days = (Time.now.utc - Time.parse(m[:last_seen].to_s)) / 86_400.0
          (m[:count].to_f * (0.5**(days / 30.0))).ceil
        rescue StandardError
          m ? m[:count].to_i : 0
        end

        private_class_method def self.previous_user(opts = {})
          sid = opts[:session_id]
          return nil unless sid && defined?(PWN::Sessions)

          t = PWN::Sessions.load(session_id: sid)
          users = t.select { |e| e[:role].to_s == 'user' }
          users.length >= 2 ? users[-2][:content] : users.last&.[](:content)
        rescue StandardError
          nil
        end

        private_class_method def self.previous_assistant(opts = {})
          sid = opts[:session_id]
          return nil unless sid && defined?(PWN::Sessions)

          t = PWN::Sessions.load(session_id: sid)
          t.rfind { |e| e[:role].to_s == 'assistant' }&.[](:content)
        rescue StandardError
          nil
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Run load and return its result
            #{self}.load

            # Run save and return its result
            #{self}.save(
              store: 'optional - store value consumed by #save'
            )

            # Run signature and return its result
            #{self}.signature(
              tool: 'required - tool/component name that failed',
              error: 'required - raw error text (will be normalised)'
            )

            # Run find and return its result
            #{self}.find(
              signature: 'optional - exact signature to fetch',
              tool: 'optional - with error:, compute signature and fetch',
              error: 'optional - raw error text (used with tool:)'
            )

            # Run for tool and return its result
            #{self}.for_tool(
              tool: 'required - tool name',
              unresolved_only: 'optional - default false'
            )

            # Run record and return its result
            #{self}.record(
              tool: 'required - tool/component that produced the failure',
              error: 'required - error text / message',
              args: 'optional - args that triggered it (stored truncated as sample)',
              session_id: 'optional - PWN::Sessions id',
              source: 'optional - :tool | :user_correction | :loop | :model | :heuristic (default :tool)',
              force: 'optional - force value consumed by #record',
              meta: 'optional - meta value consumed by #record',
              cause: 'optional - cause value consumed by #record (defaults to :self))',
              shape: 'optional - shape value consumed by #record',
              needs_code_change: 'optional - needs code change value consumed by #record'
            )

            # Run resolve and return its result
            #{self}.resolve(
              signature: 'required - mistake signature (from mistakes_list / .top)',
              fix: 'required - what to do INSTEAD next time',
              structured: 'optional - structured value consumed by #resolve',
              clear_needs_code_change: 'optional - clear needs code change value consumed by #resolve'
            )

            # Run top and return its result
            #{self}.top(
              limit: 'optional - max rows (default 10)',
              unresolved_only: 'optional - default true',
              practiceable_only: 'optional - practiceable only value consumed by #top'
            )

            # Run extinguish and return its result
            #{self}.extinguish!(
              signature: 'optional - signature value consumed by #extinguish!',
              shape: 'optional - shape value consumed by #extinguish!',
              force: 'optional - force value consumed by #extinguish!'
            )

            # Auto-resolve parked items that already have a known extinguish recipe
            #{self}.extinguish_parked!(
              limit: 'optional - limit value consumed by #extinguish_parked!',
              dry_run: 'optional - dry run value consumed by #extinguish_parked!'
            )

            # Run park and return its result
            #{self}.park(
              signature: 'required - signature value consumed by #park',
              reason: 'optional - reason value consumed by #park'
            )

            # Operator inbox: parked / needs_code_change / needs_human scars that
            #{self}.operator_inbox(
              limit: 'optional - limit value consumed by #operator_inbox'
            )

            # Run to context and return its result
            #{self}.to_context(
              limit: 'optional - limit value consumed by #to_context (defaults to 6)',
              request: 'optional - request value consumed by #to_context',
              include_open: 'optional - include open value consumed by #to_context',
              full: 'optional - full value consumed by #to_context'
            )

            # Run correction hint and return its result
            #{self}.correction_hint(
              tool: 'required - tool that just failed',
              error: 'required - raw error it failed with'
            )

            # Run correction and return its result
            #{self}.correction?(
              request: 'optional - request value consumed by #correction?'
            )

            # Run check user correction and return its result
            #{self}.check_user_correction(
              request: 'required - the incoming user message',
              session_id: 'optional - session to inspect for the previous answer'
            )

            # Run lean and return its result
            #{self}.lean!(
              dry_run: 'optional - Boolean (default false)',
              max_resolved_kept: 'optional - cap on resolved-with-fix records',
              resolved_min_age_days: 'optional - age before resolved count=1 may drop'
            )

            # Run reset and return its result
            #{self}.reset

            # Age-weighted count for [REPEATING] threshold — a ×8 signature from
            #{self}.effective_count(
              mistake: 'optional - mistake value consumed by #effective_count',
              signature: 'optional - signature value consumed by #effective_count'
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
