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
          File.write(MISTAKES_FILE, JSON.pretty_generate(store))
          store
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

          sig   = signature(tool: tool, error: error)
          store = load
          key   = sig.to_sym
          now   = Time.now.utc.iso8601
          norm  = normalize_error(error: error)

          m = store[key] ||= {
            signature: sig, tool: tool, error: norm,
            snippet: error.to_s.strip[0, 300],
            count: 0, first_seen: now, sessions: [],
            resolved: false, fix: nil, source: (opts[:source] || :tool).to_s
          }
          was_resolved     = m[:resolved]
          m[:count]       += 1
          m[:last_seen]    = now
          m[:snippet]      = error.to_s.strip[0, 300]
          m[:sample_args]  = opts[:args].to_s[0, 200] if opts[:args]
          m[:sessions]     = (Array(m[:sessions]) + [opts[:session_id]]).compact.uniq.last(10)
          # A recurrence of a "resolved" mistake means the fix was wrong /
          # incomplete — reopen it so it re-enters the DO-NOT-REPEAT block.
          m[:resolved]     = false
          m[:regressed]    = true if was_resolved
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
          save(store: store)

          if defined?(PWN::Memory)
            PWN::Memory.remember(
              key: :"mistake_fix_#{sig}",
              value: "AVOID: #{store[key][:tool]} → #{store[key][:error]} — FIX: #{fix.strip[0, 300]}",
              category: :lesson
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
          rows.sort_by { |m| [-m[:count].to_i, m[:last_seen].to_s] }.first(limit)
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
          limit  = opts[:limit] || 6
          open   = top(limit: limit, unresolved_only: true)
          closed = load.values.select { |m| m[:resolved] && m[:fix] }
                              .sort_by { |m| m[:resolved_at].to_s }.reverse.first(limit)
          return '' if open.empty? && closed.empty?

          out = +''
          unless open.empty?
            lines = open.map do |m|
              tags = []
              tags << 'REPEATING' if m[:count].to_i >= REPEAT_THRESHOLD
              tags << 'REGRESSED' if m[:regressed]
              tag = tags.empty? ? '' : " [#{tags.join(',')}]"
              fix = m[:fix] ? " — last fix (insufficient): #{m[:fix][0, 100]}" : ''
              "  ✗ [#{m[:signature]}] #{m[:tool]} ×#{m[:count]}#{tag}: #{m[:error][0, 140]}#{fix}"
            end
            out << "KNOWN MISTAKES (do NOT repeat — call mistakes_resolve once fixed)\n#{lines.join("\n")}\n"
          end
          unless closed.empty?
            lines = closed.map { |m| "  ✓ [#{m[:signature]}] #{m[:tool]}: #{m[:error][0, 80]} — FIX: #{m[:fix][0, 140]}" }
            out << "KNOWN FIXES (apply these instead of repeating the mistake)\n#{lines.join("\n")}\n"
          end
          "#{out}\n"
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
