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
            signature: sig, tool: tool, error: norm,
            snippet: error.to_s.strip[0, 300],
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
          m[:snippet]      = error.to_s.strip[0, 300]
          m[:sample_args]  = opts[:args].to_s[0, 200] if opts[:args]
          m[:sessions]     = (Array(m[:sessions]) + [opts[:session_id]]).compact.uniq.last(10)
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
          store[key][:fix]         = fix.strip[0, 500]
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
          # W1 — every resolve is a naturally-generated preference pair:
          # (rejected: the failing action, chosen: the fix).
          if defined?(Reward)
            Reward.record_preference(
              prompt: "#{store[key][:tool]}: #{store[key][:error]}",
              rejected: store[key][:snippet].to_s,
              chosen: fix.strip,
              source: :mistakes_resolve
            )
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
          rows = rows.reject { |m| m[:parked] || m[:needs_code_change] || m[:tool].to_s == 'reward_signal' } if opts[:practiceable_only]
          rows.sort_by { |m| [-m[:count].to_i, m[:last_seen].to_s] }.first(limit)
        end

        # 2.5 — park unfixable sigs so nightly practice skips them
        public_class_method def self.park(opts = {})
          sig = opts[:signature].to_s
          raise 'ERROR: signature is required' if sig.empty?

          store = load
          key = sig.to_sym
          raise "ERROR: unknown mistake signature #{sig}" unless store[key]

          store[key][:parked] = true
          store[key][:needs_code_change] = true
          store[key][:park_reason] = opts[:reason].to_s[0, 300]
          store[key][:parked_at] = Time.now.utc.iso8601
          save(store: store)
          store[key]
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
          # 2.6 — request-conditioned rank (sim × recency × count), same idea
          # as exemplars_for. Stops injecting loudest scar (reward_signal ×13)
          # on every unrelated turn.
          open = rank_for_request(rows: open_rows, request: request, limit: limit)
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
          e = opts[:error].to_s.strip.downcase
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
          e.gsub(/\s+/, ' ')[0, 300]
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
          puts <<~USAGE
            USAGE:
              PWN::AI::Agent::Mistakes.record(tool: 'shell', error: 'nmpa: command not found', args: '{"command":"nmpa -sV"}')
              PWN::AI::Agent::Mistakes.top(limit: 10, unresolved_only: true)
              PWN::AI::Agent::Mistakes.find(signature: 'abc123def456')
              PWN::AI::Agent::Mistakes.for_tool(tool: 'shell')
              PWN::AI::Agent::Mistakes.resolve(signature: 'abc123def456', fix: 'binary is spelled `nmap`, not `nmpa`')
              PWN::AI::Agent::Mistakes.correction_hint(tool: 'shell', error: err)  # inline self-correct
              PWN::AI::Agent::Mistakes.to_context(limit: 6)                        # injected by PromptBuilder
              PWN::AI::Agent::Mistakes.correction?(request: "no that's wrong")
              PWN::AI::Agent::Mistakes.check_user_correction(request: req, session_id: sid)
              PWN::AI::Agent::Mistakes.signature(tool: 'shell', error: err)
              PWN::AI::Agent::Mistakes.reset

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
