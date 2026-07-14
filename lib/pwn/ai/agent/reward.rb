# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'digest'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Reward is the OUTCOME reward model for the pwn-ai
      # reinforcement-learning loop. It replaces the regex-proxy reward that
      # previously drove Learning.infer_success / Loop.record_metrics with
      # four calibrated signals:
      #
      #   R1  .judge      — LLM Outcome Reward Model (ORM). Scores the FINAL
      #                     answer against the user request → {score:0..1,
      #                     verdict: :solved|:partial|:wrong|:refused,
      #                     rationale:}. Scalar, not boolean.
      #   R2  .prm        — Process Reward Model. Per-tool-call "did this
      #                     step advance toward the goal?" → step_reward
      #                     tagged onto every Sessions entry so credit is
      #                     assignable INSIDE a trajectory, not just at its
      #                     boundary. First PRM applied to security tooling.
      #   R3  .sentinel   — Reward-hacking detector. Tracks proxy vs judge
      #                     vs (1 - user_correction_rate); when they diverge
      #                     by > SENTINEL_GAP the reward signal itself is
      #                     fingerprinted as a Mistake so the operator sees
      #                     "your success_rate is a lie" in KNOWN MISTAKES.
      #   R4  .semantic_ok — Structured tool-result classifier. Knows that
      #                     `grep exit 1` == "no match", not "failure";
      #                     kills the phantom-mistake class (31f1871b8a15)
      #                     that made the loop's #1 negative signal a false
      #                     positive it created itself.
      #
      # Reward also owns the PREFERENCE-PAIR ledger (~/.pwn/preferences.jsonl)
      # that turns pwn's naturally-generated (rejected, chosen) pairs — from
      # user corrections, mistakes_resolve, and Curriculum.counterfactual A/B
      # branches — into a DPO export (W1). This is the ONLY path from
      # in-context learning to weight-level policy improvement.
      #
      # E3  .verify_as_reward — grounds any final containing a checkable
      # claim (CVE / version / cited URL) via Extrospection.verify and maps
      # the browser verdict onto the reward scalar. Hallucination becomes a
      # measurable −reward, not just a warning.
      #
      # Everything degrades gracefully: when module_reflection is off (no
      # LLM judge available) .judge falls back to a calibrated heuristic
      # over .semantic_ok + .verify_as_reward + Mistakes correction rate,
      # which is STILL strictly better than the old regex.
      module Reward
        PREFERENCES_FILE = File.join(Dir.home, '.pwn', 'preferences.jsonl')
        SENTINEL_FILE    = File.join(Dir.home, '.pwn', 'reward_sentinel.json')
        DPO_DIR          = File.join(Dir.home, '.pwn', 'finetune')
        SENTINEL_GAP     = 0.15
        SENTINEL_WINDOW  = 40

        VERDICTS = {
          solved: 1.0, confirmed: 1.0, partial: 0.5,
          unknown: 0.5, wrong: 0.0, refused: 0.0, refuted: 0.0
        }.freeze

        # Commands whose non-zero exit is INFORMATIONAL, not a failure. The
        # regex-proxy treating these as failures was the single largest
        # source of noise in Mistakes/Metrics (grep exit 1 = "no match").
        BENIGN_EXIT = {
          /\b(?:e|f|z|rip|p)?grep\b/ => [1],
          /\bdiff\b/ => [1],
          /\bcmp\b/ => [1],
          /\btest\b|\[\s/ => [1],
          /\bls\b/ => [1, 2],
          /\bfind\b/ => [1],
          /\bwhich\b|\bcommand -v\b/ => [1],
          /\bpidof\b|\bpgrep\b|\bpkill\b/ => [1],
          /\bxargs\b/ => [123],
          /\btimeout\b/ => [124],
          /\bcurl\b/ => [22],
          /\brubocop\b/ => [1]
        }.freeze

        JUDGE_SYSTEM = <<~SYS
          You are the pwn-ai Outcome Reward Model. Given a USER REQUEST, the
          agent's FINAL ANSWER, and a compressed TOOL TRACE, emit ONE line of
          strict JSON:
            {"score": <0.0-1.0>, "verdict": "solved|partial|wrong|refused",
             "rationale": "<≤140 chars>", "key_step": <int|-1>}
          score=1.0 only when the final DEMONSTRABLY satisfies the request
          (evidence in trace). score=0.5 for correct-direction-but-incomplete.
          score=0.0 for hallucinated / off-goal / refused. key_step is the
          1-indexed trace line most responsible for the outcome (credit
          assignment), or -1 if none. Output JSON ONLY.
        SYS

        PRM_SYSTEM = <<~SYS
          You are the pwn-ai Process Reward Model. For EACH numbered tool
          step, output one integer per line: 1 (advanced toward the goal),
          0 (neutral / exploratory), -1 (regressed / wasted). Output ONLY
          the integers, one per line, same count as steps. No prose.
        SYS

        # ----------------------------------------------------------------
        # R1 — LLM Outcome Reward Model
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # v = PWN::AI::Agent::Reward.judge(
        #   request: 'required - original user request',
        #   final: 'required - assistant final answer',
        #   session_id: 'optional - PWN::Sessions id (adds tool trace)',
        #   trace: 'optional - Array of tool-result strings (overrides session_id)',
        #   commit: 'optional - write score into learning.jsonl / sentinel (default true)'
        # )

        public_class_method def self.judge(opts = {})
          request = opts[:request].to_s
          final   = opts[:final].to_s
          trace   = Array(opts[:trace])
          trace   = load_trace(session_id: opts[:session_id]) if trace.empty? && opts[:session_id]
          commit  = opts.key?(:commit) ? opts[:commit] : true

          v = llm_judge(request: request, final: final, trace: trace)
          v ||= heuristic_judge(request: request, final: final, trace: trace)

          ground = verify_as_reward(final: final)
          unless ground.nil?
            # Ground-truth override: a browser-refuted claim caps score at
            # 0.2 regardless of how confident the judge was; a confirmed
            # claim floors it at 0.6. E3.
            v[:score] = [v[:score], 0.2].min if ground[:verdict] == :refuted
            v[:score] = [v[:score], 0.6].max if ground[:verdict] == :confirmed
            v[:grounded] = ground
          end

          v[:success] = v[:score] >= 0.6
          record_sentinel(proxy: opts[:proxy_ok], judge: v[:score]) if commit
          v
        rescue StandardError => e
          { score: 0.5, verdict: :unknown, rationale: "judge error: #{e.class}", success: !final.strip.empty?, error: e.message }
        end

        # ----------------------------------------------------------------
        # R2 — Process Reward Model (per-step credit assignment)
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # steps = PWN::AI::Agent::Reward.prm(
        #   request: 'required - user goal',
        #   session_id: 'optional - session to score in place',
        #   trace: 'optional - Array of {name:, args:, result:} or Strings'
        # )
        #
        # Returns [{idx:, step:, reward: -1|0|1}, ...] and, when session_id
        # is given, rewrites each tool line in the transcript with a
        # `[step_reward=N]` prefix so exemplars_for / distill_skill can
        # keep only reward>0 steps (C4 minimal sufficient trace).

        public_class_method def self.prm(opts = {})
          request = opts[:request].to_s
          trace   = Array(opts[:trace])
          sid     = opts[:session_id]
          trace   = load_trace(session_id: sid) if trace.empty? && sid

          rewards = llm_prm(request: request, trace: trace)
          rewards ||= heuristic_prm(trace: trace)

          out = trace.each_with_index.map do |s, i|
            { idx: i + 1, step: s.to_s[0, 200], reward: rewards[i] || 0 }
          end
          annotate_session(session_id: sid, rewards: rewards) if sid
          out
        rescue StandardError
          []
        end

        # ----------------------------------------------------------------
        # R3 — Reward-hacking sentinel
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # r = PWN::AI::Agent::Reward.sentinel

        public_class_method def self.sentinel
          s = load_sentinel
          n = s[:samples].to_i
          return { samples: n, status: :insufficient } if n < SENTINEL_WINDOW

          proxy = s[:proxy_sum].to_f / n
          judge = s[:judge_sum].to_f / n
          human = 1.0 - user_correction_rate
          gap_pj = (proxy - judge).abs
          gap_ph = (proxy - human).abs
          hacked = gap_pj > SENTINEL_GAP || gap_ph > SENTINEL_GAP
          if hacked && defined?(Mistakes)
            Mistakes.record(
              tool: 'reward_signal',
              error: "proxy success_rate #{proxy.round(2)} diverges from judge #{judge.round(2)} / human #{human.round(2)} by >#{SENTINEL_GAP}",
              source: :model
            )
          end
          { samples: n, proxy: proxy.round(3), judge: judge.round(3), human: human.round(3), gap_proxy_judge: gap_pj.round(3), gap_proxy_human: gap_ph.round(3), reward_hacked: hacked }
        end

        # ----------------------------------------------------------------
        # R4 — Structured tool-result classifier
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # h = PWN::AI::Agent::Reward.semantic_ok(
        #   name: 'required - tool name',
        #   raw: 'required - JSON string returned by Dispatch.call',
        #   args: 'optional - the tool call arguments (used for BENIGN_EXIT)'
        # )
        #
        # Returns { ok:, semantic_ok:, exit:, err:, benign: }. :ok is the old
        # proxy (handler didn't raise); :semantic_ok additionally knows that
        # grep/diff/find exit≠0 with empty stderr is not a failure. Loop.run
        # records Metrics on :ok but only records Mistakes on !semantic_ok.

        public_class_method def self.semantic_ok(opts = {})
          name = opts[:name].to_s
          raw  = opts[:raw].to_s
          ok   = raw.include?('"success":true')
          err  = raw[/"error":"([^"]{1,300})"/, 1]
          exit_code = raw[/"exit":(\d+)/, 1]&.to_i
          stderr    = raw[/"stderr":"([^"]{0,400})"/, 1].to_s

          benign = false
          if name == 'shell' && ok && exit_code && exit_code != 0
            cmd = extract_cmd(args: opts[:args])
            benign = BENIGN_EXIT.any? { |rx, codes| cmd.match?(rx) && codes.include?(exit_code) }
            benign ||= stderr.strip.empty? && exit_code == 1
          end

          semantic = ok && (exit_code.nil? || exit_code.zero? || benign)
          err ||= raw[/"stderr":"([^"]{4,300})"/, 1] unless semantic
          { ok: ok, semantic_ok: semantic, exit: exit_code, err: err, benign: benign }
        end

        # ----------------------------------------------------------------
        # E3 — verify-as-reward (ground truth without a human)
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # g = PWN::AI::Agent::Reward.verify_as_reward(final: text)

        public_class_method def self.verify_as_reward(opts = {})
          return nil unless defined?(Extrospection) && Extrospection.respond_to?(:verify)
          return nil unless agent_flag(key: :verify_as_reward, default: false)

          final = opts[:final].to_s
          claim = final[Learning::CLAIM_RX] if defined?(Learning)
          return nil if claim.to_s.empty?

          r = Extrospection.verify(claim: claim, commit: true)
          { claim: claim, verdict: r[:verdict], confidence: r[:confidence], reward: VERDICTS[r[:verdict]] || 0.5 }
        rescue StandardError
          nil
        end

        # ----------------------------------------------------------------
        # W1 — Preference-pair ledger + DPO export
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # PWN::AI::Agent::Reward.record_preference(
        #   prompt: 'required - the context / user request',
        #   rejected: 'required - the losing completion / action',
        #   chosen: 'required - the winning completion / action',
        #   source: 'optional - :user_correction | :mistakes_resolve | :counterfactual | :critic'
        # )

        public_class_method def self.record_preference(opts = {})
          prompt   = opts[:prompt].to_s
          rejected = opts[:rejected].to_s
          chosen   = opts[:chosen].to_s
          return nil if prompt.strip.empty? || chosen.strip.empty? || rejected.strip.empty?
          return nil if chosen.strip == rejected.strip

          entry = {
            id: Digest::SHA256.hexdigest("#{prompt}|#{rejected}|#{chosen}")[0, 12],
            prompt: prompt[0, 4_000],
            rejected: rejected[0, 4_000],
            chosen: chosen[0, 4_000],
            source: (opts[:source] || :unknown).to_s,
            engine: (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s,
            timestamp: Time.now.utc.iso8601
          }
          FileUtils.mkdir_p(File.dirname(PREFERENCES_FILE))
          File.open(PREFERENCES_FILE, 'a') { |f| f.puts(JSON.generate(entry)) }
          entry
        end

        # Supported Method Parameters::
        # rows = PWN::AI::Agent::Reward.preferences(limit: 500, source: nil)

        public_class_method def self.preferences(opts = {})
          limit  = opts[:limit] || 500
          source = opts[:source].to_s
          return [] unless File.exist?(PREFERENCES_FILE)

          rows = File.readlines(PREFERENCES_FILE).map do |l|
            JSON.parse(l, symbolize_names: true)
          rescue StandardError
            nil
          end
          rows.compact!
          rows.select! { |r| r[:source] == source } unless source.empty?
          rows.reverse.first(limit)
        end

        # Supported Method Parameters::
        # info = PWN::AI::Agent::Reward.export_dpo(
        #   out: 'optional - path (default ~/.pwn/finetune/pwn-dpo-YYYYMMDD.jsonl)',
        #   format: 'optional - :dpo (default) | :kto | :orpo'
        # )

        public_class_method def self.export_dpo(opts = {})
          fmt = (opts[:format] || :dpo).to_sym
          FileUtils.mkdir_p(DPO_DIR)
          out = opts[:out] || File.join(DPO_DIR, "pwn-dpo-#{Time.now.utc.strftime('%Y%m%d')}.jsonl")
          rows = preferences(limit: 100_000)
          File.open(out, 'w') do |f|
            rows.each do |r|
              line = case fmt
                     when :kto
                       [{ prompt: r[:prompt], completion: r[:chosen], label: true },
                        { prompt: r[:prompt], completion: r[:rejected], label: false }]
                     else
                       { prompt: r[:prompt], chosen: r[:chosen], rejected: r[:rejected] }
                     end
              (line.is_a?(Array) ? line : [line]).each { |l| f.puts(JSON.generate(l)) }
            end
          end
          { path: out, format: fmt, pairs: rows.length, bytes: File.size(out) }
        end

        # Supported Method Parameters::
        # PWN::AI::Agent::Reward.reset

        public_class_method def self.reset
          FileUtils.rm_f(PREFERENCES_FILE)
          FileUtils.rm_f(SENTINEL_FILE)
          { cleared: true }
        end

        # ----------------------------------------------------------------
        # privates
        # ----------------------------------------------------------------

        private_class_method def self.llm_judge(opts = {})
          return nil unless reflect_available?

          trace = opts[:trace].each_with_index.map { |s, i| "#{i + 1}. #{s.to_s.gsub(/\s+/, ' ')[0, 300]}" }.join("\n")
          req = "USER REQUEST:\n#{opts[:request][0, 1_000]}\n\nFINAL ANSWER:\n#{opts[:final][0, 2_000]}\n\nTOOL TRACE (#{opts[:trace].length} steps):\n#{trace}"
          resp = Reflect.on(request: req, system_role_content: JUDGE_SYSTEM, suppress_pii_warning: true).to_s
          j = JSON.parse(resp[/\{.*\}/m], symbolize_names: true)
          {
            score: j[:score].to_f.clamp(0.0, 1.0),
            verdict: j[:verdict].to_s.to_sym,
            rationale: j[:rationale].to_s[0, 200],
            key_step: j[:key_step].to_i,
            source: :llm_orm
          }
        rescue StandardError
          nil
        end

        private_class_method def self.llm_prm(opts = {})
          return nil unless reflect_available?
          return nil if opts[:trace].empty?

          steps = opts[:trace].each_with_index.map { |s, i| "#{i + 1}. #{s.to_s.gsub(/\s+/, ' ')[0, 250]}" }.join("\n")
          req = "GOAL: #{opts[:request][0, 400]}\n\nSTEPS:\n#{steps}"
          resp = Reflect.on(request: req, system_role_content: PRM_SYSTEM, suppress_pii_warning: true).to_s
          resp.scan(/-?1|0/).map(&:to_i).first(opts[:trace].length)
        rescue StandardError
          nil
        end

        private_class_method def self.heuristic_judge(opts = {})
          final = opts[:final]
          trace = opts[:trace]
          bad   = trace.count { |t| !semantic_ok(name: 'shell', raw: t.to_s)[:semantic_ok] }
          ratio = trace.empty? ? 1.0 : 1.0 - (bad.to_f / trace.length)
          score = final.strip.empty? ? 0.0 : ratio.clamp(0.1, 0.9)
          score = 0.0 if defined?(Learning) && final.match?(Learning::FAILURE_FINAL_RX)
          { score: score.round(2), verdict: score >= 0.6 ? :solved : :partial, rationale: 'heuristic (module_reflection off)', key_step: -1, source: :heuristic }
        end

        private_class_method def self.heuristic_prm(opts = {})
          opts[:trace].map do |t|
            s = semantic_ok(name: 'shell', raw: t.to_s)
            if s[:semantic_ok] then 1
            elsif s[:benign] then 0
            else -1
            end
          end
        end

        private_class_method def self.load_trace(opts = {})
          return [] unless opts[:session_id] && defined?(PWN::Sessions)

          entries = PWN::Sessions.load(session_id: opts[:session_id])
          user_at = entries.rindex { |e| e[:role].to_s == 'user' } || 0
          entries[user_at..].select { |e| e[:role].to_s == 'tool' }.map { |e| e[:content].to_s }
        rescue StandardError
          []
        end

        private_class_method def self.annotate_session(opts = {})
          sid = opts[:session_id]
          rewards = opts[:rewards]
          return unless sid && defined?(PWN::Sessions)

          path = File.join(PWN::Sessions.sessions_dir, "#{sid}.jsonl")
          return unless File.exist?(path)

          lines = File.readlines(path)
          ti = -1
          lines.map! do |l|
            j = JSON.parse(l, symbolize_names: true)
            if j[:role].to_s == 'tool'
              ti += 1
              j[:step_reward] = rewards[ti] if rewards[ti]
            end
            "#{JSON.generate(j)}\n"
          rescue StandardError
            l
          end
          File.write(path, lines.join)
        rescue StandardError
          nil
        end

        private_class_method def self.record_sentinel(opts = {})
          s = load_sentinel
          s[:samples]   = s[:samples].to_i + 1
          s[:judge_sum] = s[:judge_sum].to_f + opts[:judge].to_f
          s[:proxy_sum] = s[:proxy_sum].to_f + (opts[:proxy] == false ? 0.0 : 1.0) unless opts[:proxy].nil?
          # Rolling window — decay so old episodes stop dominating.
          %i[samples judge_sum proxy_sum].each { |k| s[k] = s[k].to_f * 0.9 } if s[:samples] > SENTINEL_WINDOW * 3
          FileUtils.mkdir_p(File.dirname(SENTINEL_FILE))
          File.write(SENTINEL_FILE, JSON.generate(s))
        rescue StandardError
          nil
        end

        private_class_method def self.load_sentinel
          return { samples: 0, judge_sum: 0.0, proxy_sum: 0.0 } unless File.exist?(SENTINEL_FILE)

          JSON.parse(File.read(SENTINEL_FILE), symbolize_names: true)
        rescue StandardError
          { samples: 0, judge_sum: 0.0, proxy_sum: 0.0 }
        end

        private_class_method def self.user_correction_rate
          return 0.0 unless defined?(Learning)

          rows = Learning.outcomes(limit: 200)
          return 0.0 if rows.empty?

          rows.count { |r| r[:flipped_by].to_s == 'user_correction' }.to_f / rows.length
        rescue StandardError
          0.0
        end

        private_class_method def self.extract_cmd(opts = {})
          a = opts[:args]
          h = a.is_a?(String) ? JSON.parse(a, symbolize_names: true) : a
          # Leading env-vars / sudo / pipes: match any segment.
          h.is_a?(Hash) ? h[:command].to_s.strip : a.to_s
        rescue StandardError
          opts[:args].to_s
        end

        private_class_method def self.reflect_available?
          defined?(Reflect) && defined?(PWN::Env) && PWN::Env.is_a?(Hash) && PWN::Env.dig(:ai, :module_reflection)
        rescue StandardError
          false
        end

        private_class_method def self.agent_flag(opts = {})
          v = (PWN::Env.dig(:ai, :agent, opts[:key]) if defined?(PWN::Env))
          v.nil? ? opts[:default] : v
        rescue StandardError
          opts[:default]
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts <<~USAGE
            USAGE:
              # Tier 1 — reward signal
              PWN::AI::Agent::Reward.judge(request: req, final: text, session_id: sid)     # R1 ORM → {score:, verdict:, rationale:}
              PWN::AI::Agent::Reward.prm(request: req, session_id: sid)                    # R2 PRM → per-step credit
              PWN::AI::Agent::Reward.sentinel                                              # R3 reward-hacking detector
              PWN::AI::Agent::Reward.semantic_ok(name: 'shell', raw: json, args: args)     # R4 kills phantom exit≠0 mistakes

              # Tier 5 — preference pairs → DPO
              PWN::AI::Agent::Reward.record_preference(prompt: p, rejected: r, chosen: c, source: :user_correction)
              PWN::AI::Agent::Reward.preferences(limit: 100)
              PWN::AI::Agent::Reward.export_dpo(format: :dpo)                              # W1 → ~/.pwn/finetune/pwn-dpo-*.jsonl

              # Tier 6 — grounded reward
              PWN::AI::Agent::Reward.verify_as_reward(final: text)                         # E3 browser-verified reward

              Config (PWN::Env[:ai][:agent]):
                :verify_as_reward   - Boolean, ground every final via extro_verify (default false)

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
