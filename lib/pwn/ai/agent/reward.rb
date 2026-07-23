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
          s = normalize_sentinel(raw: load_sentinel)
          window = s[:window]
          n = window.length
          return { samples: n, status: :insufficient } if n < SENTINEL_WINDOW

          means = window_means(window: window)
          proxy = means[:proxy]
          judge = means[:judge]
          # Refuse to act on corrupt arithmetic — proxy must be a rate in [0,1].
          if proxy.nil? || proxy < 0.0 || proxy > 1.0
            return {
              samples: n,
              status: :corrupt_proxy,
              proxy: proxy,
              judge: judge&.round(3),
              reward_hacked: false,
              proxy_distrust: proxy_distrust
            }
          end

          human = 1.0 - user_correction_rate
          gap_pj = (proxy - judge).abs
          gap_ph = (proxy - human).abs
          hacked = gap_pj > SENTINEL_GAP || gap_ph > SENTINEL_GAP
          if hacked
            # 1.1 — freeze auto-Mistakes.record on tool:reward_signal after the
            # first open sig per gap-bucket. Endless ×13 fingerprints were
            # the loudest scar in every prompt and taught nothing. Open a
            # calibration path instead; park the sig as needs_code_change.
            bucket = "gap_pj=#{gap_pj.round(2)}|gap_ph=#{gap_ph.round(2)}"
            open_sig = defined?(Mistakes) ? Mistakes.for_tool(tool: 'reward_signal', unresolved_only: true) : []
            if open_sig.empty? && defined?(Mistakes)
              m = Mistakes.record(
                tool: 'reward_signal',
                error: "proxy success_rate #{proxy.round(2)} diverges from judge #{judge.round(2)} / human #{human.round(2)} by >#{SENTINEL_GAP}",
                source: :model,
                needs_code_change: true,
                meta: { bucket: bucket, proxy: proxy, judge: judge, human: human }
              )
              Mistakes.park(signature: m[:signature], reason: 'reward_signal needs calibration, not practice') if m && Mistakes.respond_to?(:park)
            end
            Curriculum.calibrate(predicted: proxy, actual: judge, engine: :reward_sentinel) if defined?(Curriculum) && Curriculum.respond_to?(:calibrate)
            # P4 — make sentinel ACTIONABLE: persist a distrust factor so
            # Metrics.to_context / Registry.rank haircut proxy success instead of
            # just opening another Mistakes row the model learns to ignore.
            set_proxy_distrust(gap: [gap_pj, gap_ph].max, proxy: proxy, judge: judge)
          else
            clear_proxy_distrust
          end
          {
            samples: n,
            proxy: proxy.round(3),
            judge: judge.round(3),
            human: human.round(3),
            gap_proxy_judge: gap_pj.round(3),
            gap_proxy_human: gap_ph.round(3),
            reward_hacked: hacked,
            proxy_distrust: proxy_distrust
          }
        end

        # P4 — scalar 0.0..1.0 haircut applied to Metrics success / Registry β when
        # the proxy is lying. 0.0 = trust proxy fully; 1.0 = ignore proxy rates.
        public_class_method def self.proxy_distrust
          s = load_sentinel
          d = s[:proxy_distrust].to_f
          # auto-expire after 7d without refresh so a one-off gap doesn't stick
          if s[:distrust_at]
            age = Time.now.utc - Time.parse(s[:distrust_at].to_s)
            return 0.0 if age > 7 * 86_400
          end
          d.clamp(0.0, 1.0)
        rescue StandardError
          0.0
        end

        public_class_method def self.set_proxy_distrust(opts = {})
          s = normalize_sentinel(raw: load_sentinel)
          gap = opts[:gap].to_f
          proxy = opts[:proxy]
          # Guard: never set distrust from a nonsensical proxy (pre-ring-buffer
          # decay×to_i bug produced means ≫ 1.0 and hard-pegged distrust at 1.0).
          unless proxy.nil?
            pf = proxy.to_f
            return s[:proxy_distrust].to_f if pf < 0.0 || pf > 1.0
          end
          # map gap 0.15→0.4, 0.30→0.8, ≥0.40→1.0
          factor = ((((gap - SENTINEL_GAP) / SENTINEL_GAP) * 0.4) + 0.4).clamp(0.3, 1.0)
          s[:proxy_distrust] = factor
          s[:distrust_at] = Time.now.utc.iso8601
          s[:distrust_meta] = { proxy: opts[:proxy], judge: opts[:judge], gap: gap }
          FileUtils.mkdir_p(File.dirname(SENTINEL_FILE))
          atomic_write(path: SENTINEL_FILE, body: JSON.generate(s))
          factor
        rescue StandardError
          nil
        end

        public_class_method def self.clear_proxy_distrust
          s = load_sentinel
          return if s[:proxy_distrust].to_f <= 0.0

          s[:proxy_distrust] = 0.0
          s[:distrust_cleared_at] = Time.now.utc.iso8601
          atomic_write(path: SENTINEL_FILE, body: JSON.generate(s))
        rescue StandardError
          nil
        end

        # One-shot: wipe sentinel window + distrust after deploying the
        # ring-buffer arithmetic (or any time the live file is known-corrupt).
        # Does NOT touch preferences / DPO exports (unlike .reset).
        public_class_method def self.reset_sentinel
          FileUtils.rm_f(SENTINEL_FILE)
          { cleared: true, path: SENTINEL_FILE }
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
          shape  = nil
          if name == 'shell' && ok && exit_code && exit_code != 0
            cmd = extract_cmd(args: opts[:args])
            # 2.1 — ONLY BENIGN_EXIT regex × allowed codes. The old global
            # `stderr.empty? && exit==1 ⇒ benign` laundered real failures
            # (pipelines without pipefail, bare false, etc.) into "success".
            # For pipelines, match the LAST stage (post-pipe) first, then any.
            stages = cmd.split('|').map(&:strip)
            last   = stages.last.to_s
            benign = BENIGN_EXIT.any? { |rx, codes| last.match?(rx) && codes.include?(exit_code) }
            benign ||= stages.length > 1 && BENIGN_EXIT.any? { |rx, codes| stages.any? { |s| s.match?(rx) } && codes.include?(exit_code) && stderr.strip.empty? }
            shape = recoverable_shape(exit_code: exit_code, stderr: stderr, err: err)
          elsif !ok
            shape = recoverable_shape(exit_code: exit_code, stderr: stderr, err: err || raw[0, 200])
          end

          semantic = ok && (exit_code.nil? || exit_code.zero? || benign)
          err ||= raw[/"stderr":"([^"]{4,300})"/, 1] unless semantic
          { ok: ok, semantic_ok: semantic, exit: exit_code, err: err, benign: benign, shape: shape }
        end

        # 2.2 — coarse recoverable shape beside the fingerprint. Paths are
        # normalised away for counting; shape stays for repair routing
        # (enoent → install/check path; exit127 → missing binary; …).
        public_class_method def self.recoverable_shape(opts = {})
          err = "#{opts[:err]} #{opts[:stderr]}".downcase
          ec  = opts[:exit_code]
          return :exit127 if ec == 127 || err.include?('command not found')
          return :exit126 if ec == 126
          return :enoent if err.match?(/no such file|enoent|cannot access|not a directory/)
          return :eacces if err.match?(/permission denied|eacces|operation not permitted/)
          return :auth_required if err.match?(/auth|unauthorized|401|403|forbidden|login required|api.?key/)
          return :timeout if ec == 124 || err.include?('timed out') || err.include?('timeout')
          return :network if err.match?(/connection refused|name or service not known|could not resolve|network is unreachable/)
          return :syntax if err.match?(/syntax error|parse error|unexpected token|json::parser/)
          return :nonzero_exit if ec && ec != 0
          return :handler_error if err.strip.length.positive?

          :unknown
        end

        # ----------------------------------------------------------------
        # E3 — verify-as-reward (ground truth without a human)
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # g = PWN::AI::Agent::Reward.verify_as_reward(final: text)

        public_class_method def self.verify_as_reward(opts = {})
          return nil unless defined?(Extrospection) && Extrospection.respond_to?(:verify)

          final = opts[:final].to_s
          claim = final[Learning::CLAIM_RX] if defined?(Learning)
          return nil if claim.to_s.empty?

          # 1.5 — sampled E3: always when flag true; never when false;
          # nil/auto → always on frontier, ~10% on local when CLAIM_RX hits.
          flag = agent_flag(key: :verify_as_reward, default: nil)
          eng  = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s.downcase
          local = eng == 'ollama'
          run = case flag
                when true then true
                when false then false
                else
                  local ? (Digest::SHA256.hexdigest(claim.to_s)[0, 2].to_i(16) % 10).zero? : true
                end
          return nil unless run

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

        # Max share any single preference source may occupy in a DPO export.
        # Without this cap, mistakes_resolve monoculture (often >80%) teaches
        # the LoRA "emit fix prose" instead of trajectory preference (P5 enforce).
        DPO_SOURCE_CAP = 0.40

        public_class_method def self.export_dpo(opts = {})
          fmt = (opts[:format] || :dpo).to_sym
          FileUtils.mkdir_p(DPO_DIR)
          out = opts[:out] || File.join(DPO_DIR, "pwn-dpo-#{Time.now.utc.strftime('%Y%m%d')}.jsonl")
          rows = preferences(limit: 100_000)
          # P5 — downsample so no single source exceeds DPO_SOURCE_CAP of the export.
          # opt-out with balance: false (raw dump for diagnostics).
          balance = opts.key?(:balance) ? opts[:balance] : true
          selected = balance ? balance_preference_rows(rows: rows, cap: (opts[:source_cap] || DPO_SOURCE_CAP).to_f) : rows
          dropped = rows.length - selected.length
          File.open(out, 'w') do |f|
            selected.each do |r|
              line = case fmt
                     when :kto
                       [{ prompt: r[:prompt], completion: r[:chosen], label: true },
                        { prompt: r[:prompt], completion: r[:rejected], label: false }]
                     else
                       # Keep source for auditability / preference_balance post-export.
                       { prompt: r[:prompt], chosen: r[:chosen], rejected: r[:rejected], source: r[:source] }
                     end
              (line.is_a?(Array) ? line : [line]).each { |l| f.puts(JSON.generate(l)) }
            end
          end
          by_src = selected.group_by { |r| r[:source].to_s }.transform_values(&:length)
          {
            path: out, format: fmt, pairs: selected.length, bytes: File.size(out),
            balanced: balance, dropped: dropped, by_source: by_src,
            source_cap: balance ? (opts[:source_cap] || DPO_SOURCE_CAP).to_f : nil
          }
        end

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

          # Annotate each step with R4 semantic_ok/benign so the PRM teacher
          # does not anti-correlate recon (grep miss / find empty) with −1.
          steps = opts[:trace].each_with_index.map do |s, i|
            raw = s.to_s
            sem = semantic_ok(name: 'shell', raw: raw)
            tag = if sem[:benign] then ' [R4:benign_nonzero]'
                  elsif sem[:semantic_ok] then ' [R4:ok]'
                  else ' [R4:fail]'
                  end
            "#{i + 1}.#{tag} #{raw.gsub(/\s+/, ' ')[0, 220]}"
          end.join("\n")
          req = "GOAL: #{opts[:request][0, 400]}\n\n" \
                'R4 tags: [R4:ok]=tool succeeded, [R4:benign_nonzero]=informational ' \
                "non-zero (grep/diff/find miss — score 0 not -1), [R4:fail]=real failure.\n\n" \
                "STEPS:\n#{steps}"
          resp = Reflect.on(request: req, system_role_content: PRM_SYSTEM, suppress_pii_warning: true).to_s
          resp.scan(/-?1|0/).map(&:to_i).first(opts[:trace].length)
        rescue StandardError
          nil
        end

        private_class_method def self.heuristic_judge(opts = {})
          final   = opts[:final].to_s
          request = opts[:request].to_s
          trace   = opts[:trace]
          # 1.4 — empty / polite / failure-language finals cannot score high
          # just because tools mostly returned handler-ok.
          return { score: 0.0, verdict: :wrong, rationale: 'empty final', key_step: -1, source: :heuristic } if final.strip.empty?
          return { score: 0.0, verdict: :wrong, rationale: 'failure-language final', key_step: -1, source: :heuristic } if defined?(Learning) && final.match?(Learning::FAILURE_FINAL_RX)

          polite = final.match?(/\A\s*(sure|happy to help|of course|i can help|how can i|let me know)\b/i) && final.length < 120
          return { score: 0.1, verdict: :partial, rationale: 'polite non-answer', key_step: -1, source: :heuristic } if polite && trace.empty?

          bad   = trace.count { |t| !semantic_ok(name: 'shell', raw: t.to_s)[:semantic_ok] }
          ratio = trace.empty? ? 0.5 : 1.0 - (bad.to_f / trace.length)
          score = ratio.clamp(0.1, 0.9)

          # require claim ↔ request token overlap (stops "non-empty + ok tools"
          # from looking solved when the final never addressed the ask)
          req_toks = request.downcase.scan(/[a-z0-9_]{3,}/).uniq
          fin_toks = final.downcase.scan(/[a-z0-9_]{3,}/).uniq
          overlap  = req_toks.empty? ? 1.0 : (req_toks & fin_toks).length.to_f / req_toks.length
          score   *= (0.4 + (0.6 * overlap))
          score    = [score, 0.45].min if overlap < 0.15 && req_toks.length >= 3

          # trace evidence: if tools ran, prefer finals that echo something from them
          if trace.any?
            blob = trace.join(' ')[0, 2_000].downcase
            echoed = fin_toks.count { |t| t.length >= 4 && blob.include?(t) }
            score *= 0.7 if echoed.zero? && final.length > 40
          end

          score = score.round(2).clamp(0.0, 0.9)
          verdict = if score >= 0.6 then :solved
                    elsif score >= 0.3 then :partial
                    else :wrong
                    end
          { score: score, verdict: verdict, rationale: "heuristic overlap=#{overlap.round(2)} ratio=#{ratio.round(2)}", key_step: -1, source: :heuristic }
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
          s = normalize_sentinel(raw: load_sentinel)
          # Clamp judge to [0,1] — LLM/heuristic should already, but a bad
          # write must not poison rolling means forever.
          judge = opts[:judge].to_f.clamp(0.0, 1.0)
          entry = { judge: judge, at: Time.now.utc.iso8601 }
          # 1.3 — only roll proxy into the window when the caller actually
          # supplied a R4-aligned proxy_ok. Pre-ORM boolean noise no longer
          # dilutes gap_proxy_judge. Proxy is ALWAYS 0.0 or 1.0 when present.
          unless opts[:proxy].nil?
            entry[:proxy] = opts[:proxy] ? 1.0 : 0.0
          end
          s[:window] = (Array(s[:window]) + [entry]).last(SENTINEL_WINDOW)
          # Derived counters kept for back-compat with Learning.stats / operators
          # that still read samples/proxy_sum/proxy_n from the on-disk file.
          means = window_means(window: s[:window])
          s[:samples]   = s[:window].length
          s[:judge_sum] = s[:window].sum { |e| e[:judge].to_f }
          proxied = s[:window].reject { |e| e[:proxy].nil? }
          s[:proxy_n]   = proxied.length
          s[:proxy_sum] = proxied.sum { |e| e[:proxy].to_f }
          s[:proxy_mean] = means[:proxy]
          s[:judge_mean] = means[:judge]
          FileUtils.mkdir_p(File.dirname(SENTINEL_FILE))
          atomic_write(path: SENTINEL_FILE, body: JSON.generate(s))
        rescue StandardError
          nil
        end

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

        private_class_method def self.load_sentinel
          return empty_sentinel unless File.exist?(SENTINEL_FILE)

          normalize_sentinel(raw: JSON.parse(File.read(SENTINEL_FILE), symbolize_names: true))
        rescue StandardError
          empty_sentinel
        end

        # Empty / default on-disk shape. :window is the sole source of truth
        # for rolling means; sum/n fields are derived projections.
        private_class_method def self.empty_sentinel
          {
            window: [],
            samples: 0,
            judge_sum: 0.0,
            proxy_sum: 0.0,
            proxy_n: 0,
            proxy_distrust: 0.0
          }
        end

        # Migrate legacy {samples, judge_sum, proxy_sum, proxy_n} decaying-sum
        # files onto a fixed ring buffer. Legacy sums are NOT replayed into
        # synthetic samples — decay×to_i desync made proxy_sum/proxy_n
        # untrustworthy (means ≫ 1). Fresh window starts empty; distrust is
        # cleared so a corrupt detector cannot keep blinding Metrics.
        private_class_method def self.normalize_sentinel(opts = {})
          raw = opts.is_a?(Hash) && opts.key?(:raw) ? opts[:raw] : opts
          s = (raw.is_a?(Hash) ? raw.dup : empty_sentinel)
          s[:window] = Array(s[:window]).map do |e|
            next nil unless e.is_a?(Hash)

            h = { judge: e[:judge].to_f.clamp(0.0, 1.0) }
            h[:at] = e[:at] if e[:at]
            unless e[:proxy].nil?
              pv = e[:proxy]
              pv = 1.0 if pv == true || pv.to_s == 'true'
              pv = 0.0 if pv == false || pv.to_s == 'false'
              pv = pv.to_f
              next nil if pv < 0.0 || pv > 1.0

              h[:proxy] = pv
            end
            h
          end.compact.last(SENTINEL_WINDOW)

          # Drop legacy decaying counters so operators do not re-read them as truth.
          if s[:window].empty?
            s[:samples] = 0
            s[:judge_sum] = 0.0
            s[:proxy_sum] = 0.0
            s[:proxy_n] = 0
            # Corrupt legacy file (proxy mean outside [0,1]) → clear stuck distrust.
            legacy_pn = raw.is_a?(Hash) ? raw[:proxy_n].to_i : 0
            legacy_ps = raw.is_a?(Hash) ? raw[:proxy_sum].to_f : 0.0
            if legacy_pn.positive?
              legacy_mean = legacy_ps / legacy_pn
              if legacy_mean < 0.0 || legacy_mean > 1.0
                s[:proxy_distrust] = 0.0
                s[:distrust_cleared_at] ||= Time.now.utc.iso8601
                s[:distrust_meta] = {
                  reason: 'legacy_corrupt_proxy_mean',
                  legacy_proxy_mean: legacy_mean,
                  cleared: true
                }
                s.delete(:distrust_at)
              end
            end
          else
            means = window_means(window: s[:window])
            s[:samples] = s[:window].length
            s[:judge_sum] = s[:window].sum { |e| e[:judge].to_f }
            proxied = s[:window].reject { |e| e[:proxy].nil? }
            s[:proxy_n] = proxied.length
            s[:proxy_sum] = proxied.sum { |e| e[:proxy].to_f }
            s[:proxy_mean] = means[:proxy]
            s[:judge_mean] = means[:judge]
          end
          s
        end

        private_class_method def self.window_means(opts = {})
          w = Array(opts.is_a?(Hash) && opts.key?(:window) ? opts[:window] : opts)
          return { proxy: nil, judge: 0.0 } if w.empty?

          judge = w.sum { |e| e[:judge].to_f } / w.length
          proxied = w.reject { |e| e[:proxy].nil? }
          proxy = if proxied.empty?
                    nil
                  else
                    proxied.sum { |e| e[:proxy].to_f } / proxied.length
                  end
          { proxy: proxy, judge: judge }
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

        # P5 enforce — downsample so no source exceeds `cap` of the FINAL export.
        # Keeps newest rows first (preferences() already newest-first).
        # Single-source corpora are left intact (cannot diversify what is absent);
        # multi-source corpora are iteratively clipped until every share ≤ cap.
        private_class_method def self.balance_preference_rows(opts = {})
          rows = Array(opts[:rows])
          cap  = (opts[:cap] || DPO_SOURCE_CAP).to_f
          cap  = 0.40 if cap <= 0.0 || cap > 1.0
          return rows if rows.length < 5

          id_order = rows.each_with_index.to_h { |r, i| [r[:id] || r.object_id, i] }
          by = rows.group_by { |r| r[:source].to_s.empty? ? 'unknown' : r[:source].to_s }
                   .transform_values(&:dup)
          return rows if by.length < 2

          64.times do
            total = by.values.sum(&:length)
            break if total.zero?

            worst_src, worst_list = by.max_by { |_, list| list.length }
            share = worst_list.length.to_f / total
            break if share <= (cap + 1e-9)

            # max allowed from greediest source given current total of the others
            others = total - worst_list.length
            # want keep/(keep+others) ≤ cap  ⇒  keep ≤ cap/(1-cap) * others
            max_keep = if (1.0 - cap).positive?
                         [((cap / (1.0 - cap)) * others).floor, 1].max
                       else
                         1
                       end
            max_keep = [max_keep, worst_list.length - 1].min
            break if max_keep < 1 || max_keep >= worst_list.length

            by[worst_src] = worst_list.first(max_keep)
          end

          selected = by.values.flatten
          selected.sort_by { |r| id_order[r[:id] || r.object_id] || 0 }
        rescue StandardError
          rows
        end

        # ORM/PRM teacher availability.
        # module_reflection gates Reflect lesson writing; reward models need a
        # teacher even when that is off. For remote engines default ON so grok
        # answers are not graded by a shell-exit heuristic. Local ollama stays
        # heuristic unless module_reflection or agent.reward_llm is true.
        private_class_method def self.reflect_available?
          return false unless defined?(Reflect) && defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          return true if PWN::Env.dig(:ai, :module_reflection)

          flag = PWN::Env.dig(:ai, :agent, :reward_llm)
          return flag ? true : false unless flag.nil?

          eng = PWN::Env.dig(:ai, :active).to_s.downcase
          !(eng.empty? || eng == 'ollama')
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
              PWN::AI::Agent::Reward.reset_sentinel                                        # wipe corrupt window + distrust
              PWN::AI::Agent::Reward.semantic_ok(name: 'shell', raw: json, args: args)     # R4 kills phantom exit≠0 mistakes

              # Tier 5 — preference pairs → DPO
              PWN::AI::Agent::Reward.record_preference(prompt: p, rejected: r, chosen: c, source: :user_correction)
              PWN::AI::Agent::Reward.preferences(limit: 100)
              PWN::AI::Agent::Reward.export_dpo(format: :dpo)                              # W1 → ~/.pwn/finetune/pwn-dpo-*.jsonl (≤40%/source)
              PWN::AI::Agent::Reward.export_dpo(format: :dpo, balance: false)              # raw dump (diagnostics)

              # Tier 6 — grounded reward
              PWN::AI::Agent::Reward.verify_as_reward(final: text)                         # E3 browser-verified reward

              Config (PWN::Env[:ai][:agent]):
                :verify_as_reward   - Boolean/nil, ground finals via extro_verify (nil=auto)
                :reward_llm         - Boolean/nil, force ORM/PRM LLM teacher (nil=on for remote engines)

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
