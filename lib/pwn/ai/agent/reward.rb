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
      # .judge prefers a cheap LLM ORM (direct engine .chat, short timeout,
      # no Reflect / module_reflection gate). Reflect.on is used only when
      # the operator enabled module_reflection (teacher engine). Heuristic
      # token-overlap is LAST RESORT so proxy_distrust haircuts blend toward
      # a real outcome signal, not bag-of-words overlap.
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
          Grade the HUMAN RESULT against the USER REQUEST only — never a TUI
          plan, stub outline, or competing compass:
            1.0 = final is usable and complete (every asked point answered with
                  evidence from the trace or a checkable claim).
            0.7 = mostly complete, one missing detail, still usable.
            0.5 = correct direction but incomplete / truncated.
            0.2 = tools ran but the final does not answer the ask.
            0.0 = hallucinated, off-goal, empty, polite non-answer, or refused.
          Ignore {"success":true} as evidence of done. Prefer last tool steps.
          key_step is the 1-indexed shown-trace line most responsible, or -1.
          Output JSON ONLY. No markdown fences.
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
          # Cheap ORM is the intended source. Heuristic overlap is fallback
          # only — callers (sentinel / Learning.stats / Metrics.effective_rate)
          # weight :llm_orm samples above :heuristic so the haircut tracks
          # the outcome model, not token overlap.

          # P1 — local/heuristic calibration: thin judges must not be treated
          # as ground truth when proxy_distrust is already high. Two levers:
          #   (1) low :confidence so Metrics.effective_rate haircuts blend
          #       weight (distrust × confidence) instead of replacing proxy;
          #   (2) score-path caps only for decisive failure floors and for
          #       local no-trace highs (false "solved"). Do NOT pull known
          #       wrong (0.0 failure-language) toward 0.5, and do NOT deflate
          #       tool-backed heuristic scores that already cleared the bar —
          #       confidence handles that in the bandit blend.
          eng = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s.downcase
          local = eng == 'ollama' || eng.empty?
          if v[:source].to_s == 'heuristic' || v[:source].to_s.start_with?('heuristic')
            toolbacked = Array(trace).any?
            v[:heuristic_class] = toolbacked ? :toolbacked : :textual
            v[:source] = :heuristic
            v[:confidence] = if toolbacked
                               local ? 0.55 : 0.7
                             else
                               local ? 0.35 : 0.5
                             end
            raw = v[:score].to_f
            v[:score_raw] = raw
            if !toolbacked && local && raw > 0.15 && trace.empty? && raw >= 0.6 && final.length < 400
              v[:score] = [raw, 0.45].min
              v[:rationale] = "#{v[:rationale]} | P1:local_no_trace_cap"
            elsif !toolbacked && local && raw > 0.15 && trace.length < 2 && raw >= 0.85
              v[:score] = (0.5 + ((raw - 0.5) * 0.7)).round(3).clamp(0.0, 1.0)
            else
              v[:score] = raw
            end
            v[:verdict] = if v[:score] >= 0.6 then :solved
                          elsif v[:score] >= 0.3 then :partial
                          else :wrong
                          end
          else
            v[:confidence] ||= 0.85
          end

          ground = verify_as_reward(final: final)
          unless ground.nil?
            # Ground-truth override: a browser-refuted claim caps score at
            # 0.2 regardless of how confident the judge was; a confirmed
            # claim floors it at 0.6. E3.
            v[:score] = [v[:score], 0.2].min if ground[:verdict] == :refuted
            v[:score] = [v[:score], 0.6].max if ground[:verdict] == :confirmed
            v[:grounded] = ground
            v[:confidence] = [v[:confidence].to_f, ground[:confidence].to_f].max if ground[:confidence]
          end

          pass = final.match?(/\bPASS\b/) && !(defined?(Learning) && final.match?(Learning::FAILURE_FINAL_RX))
          v[:judge_score] = v[:score].to_f
          vv = opts[:verifier_verdict]
          vv = :pass if vv.nil? && (opts[:verifier_pass] == true || pass || (ground && ground[:verdict] == :confirmed))
          vv = vv.to_s.to_sym if vv
          v[:verifier_verdict] = vv
          v[:verdict_class] = taxonomy_class(opts.merge(score: v[:score], verifier_verdict: vv, request: request, final: final))
          v[:remediation_hint] = taxonomy_hint(verdict_class: v[:verdict_class])
          prec = verifier_precedence?
          if prec && vv == :pass
            v[:success] = true
          else
            v[:success] = promote_to_success?(
              orm: v[:source].to_s != 'heuristic' && v[:score].to_f >= 0.6,
              verify: if ground.nil?
                        nil
                      else
                        ground[:verdict] == :confirmed
                      end,
              critic: opts.key?(:critic_pass) ? opts[:critic_pass] : nil
            )
          end
          v[:needs_spot_check] = v[:success] && v[:score].to_f >= 0.85 && (rand < 0.05)
          v[:engine] = eng
          v[:task_class] = request.match?(/analy[sz]e|summar|strength|weakness|fitness/i) ? 'analysis' : 'operational'
          if pass
            score = v[:score].to_f
            v[:score] = [score, 0.6].max
            v[:success] = true if prec
            v[:verifier_verdict] ||= :pass
            v[:verdict] = :solved
          end
          v[:score_components] ||= {
            judge: v[:score].to_f,
            overlap: pass ? 0.0 : nil,
            checks: 0.0,
            weights: { overlap: pass ? 0.0 : 0.15 }
          }
          v[:score_components][:weights][:overlap] = 0.0 if pass
          if commit && defined?(Learning) && opts[:persist_components]
            Learning.note_outcome(
              task: request[0, 80],
              success: v[:success],
              score: v[:score],
              details: v[:score_components].to_json,
              verifier_verdict: v[:verifier_verdict],
              verdict_class: v[:verdict_class]
            )
          end
          # W3 — write Brier on every judged turn so overconfidence can
          # throttle max_iters/critic even when plan_first never fired.
          if commit
            pred = opts[:predicted]
            pred = Thread.current[:pwn_plan_predicted] if pred.nil?
            pred = v[:confidence] if pred.nil?
            Curriculum.calibrate(predicted: pred, actual: v[:score], engine: eng) if defined?(Curriculum) && Curriculum.respond_to?(:calibrate)
          end
          # P1 — sentinel stores confidence so distrust math can haircut
          # heuristic-heavy windows differently from LLM ORM windows.
          record_sentinel(proxy: opts[:proxy_ok], judge: v[:score], confidence: v[:confidence], source: v[:source]) if commit
          v
        rescue StandardError => e
          { score: 0.5, verdict: :unknown, rationale: "judge error: #{e.class}", success: !final.strip.empty?, error: e.message, confidence: 0.2, source: :error }
        end

        public_class_method def self.promote_to_success?(opts = {})
          flags = []
          flags << (opts[:orm] ? true : false) unless opts[:orm].nil?
          flags << (opts[:verify] ? true : false) unless opts[:verify].nil?
          flags << (opts[:critic] ? true : false) unless opts[:critic].nil?
          return false if flags.empty?
          return flags.first if flags.length == 1

          flags.count(true) >= 2
        end

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
        # Plan-quality soft signal (W3 feature / Learning tag)
        # ----------------------------------------------------------------
        # Cheap heuristic: did the final (+ optional tool trace) cover the
        # tangible plan tasks? Not full DPO — trajectory-shaped pairs come
        # later. Score is a soft feature for calibration / tagging only.
        #
        # Supported Method Parameters::
        # r = PWN::AI::Agent::Reward.plan_coverage(
        #   plan: 'required - Array of task strings or outline text',
        #   final: 'required - assistant final answer',
        #   request: 'optional - original user request',
        #   trace: 'optional - Array of tool-result strings',
        #   session_id: 'optional - load trace from session when trace empty'
        # )
        # => { score: 0.0..1.0, covered: N, total: M, missing: [...], tag: 'plan_cover_high|mid|low' }
        public_class_method def self.plan_coverage(opts = {})
          plan = opts[:plan]
          tasks =
            case plan
            when Array then plan.map(&:to_s)
            when String
              if defined?(TaskSummarizer) && TaskSummarizer.respond_to?(:parse_outline_tasks)
                TaskSummarizer.parse_outline_tasks(outline: plan)
              else
                plan.to_s.split(/\n+/).map { |l| l.sub(/\A(?:\d+[.):]|[-*•])\s+/, '').strip }
              end
            else
              Array(plan).map(&:to_s)
            end
          tasks = tasks.map { |t| t.to_s.gsub(/\s+/, ' ').strip }.reject(&:empty?)
          return { score: 0.0, covered: 0, total: 0, missing: [], tag: 'plan_cover_none' } if tasks.empty?

          final = opts[:final].to_s
          request = opts[:request].to_s
          trace = Array(opts[:trace])
          trace = load_trace(session_id: opts[:session_id]) if trace.empty? && opts[:session_id]
          blob = "#{final}\n#{request}\n#{trace.join("\n")}".downcase

          covered = []
          missing = []
          tasks.each do |task|
            stems = task.downcase.scan(/[a-z0-9]{4,}/).uniq
            # Drop ultra-generic plan fillers that would false-positive everything.
            stems.reject! { |s| %w[result results report verify complete completion present carry work task step this that with from into].include?(s) }
            if stems.empty?
              covered << task
              next
            end
            # A task is covered when >= half of its distinctive stems appear
            # in final+trace (soft — not DPO-grade evidence).
            hits = stems.count { |s| blob.include?(s) }
            need = [1, (stems.length / 2.0).ceil].max
            if hits >= need
              covered << task
            else
              missing << task
            end
          end

          total = tasks.length
          score = (covered.length.to_f / total).round(3).clamp(0.0, 1.0)
          tag =
            if score >= 0.75 then 'plan_cover_high'
            elsif score >= 0.4 then 'plan_cover_mid'
            else 'plan_cover_low'
            end
          {
            score: score,
            covered: covered.length,
            total: total,
            missing: missing.first(6),
            tag: tag
          }
        rescue StandardError
          { score: 0.0, covered: 0, total: 0, missing: [], tag: 'plan_cover_error' }
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
          d = d.clamp(0.0, 1.0)
          # Recalibrated cap: leftover 1.0 from the old mapping must not fully
          # haircut raw success unless the live gap is still extreme.
          meta = s[:distrust_meta] || {}
          gap = (meta[:gap] || meta['gap']).to_f
          [d, 0.85].min
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
          # Recalibrated: do NOT full-haircut raw success. 0.15→0.25, 0.30→0.50,
          # 0.45→0.70, hard cap 0.85 unless the gap is extreme (≥0.55 → 0.95).
          factor = ((((gap - SENTINEL_GAP) / SENTINEL_GAP) * 0.5) + 0.25).clamp(0.2, 0.85)
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

        # P10 — backfill the R3 ring from Learning outcomes so offline/local
        # hosts reach SENTINEL_WINDOW without waiting for live remote
        # introspect. Only fills empty slots; never flushes a warm window.
        # Called by Curriculum.offline_judge and safe to cron.
        public_class_method def self.warm_sentinel(opts = {})
          s = normalize_sentinel(raw: load_sentinel)
          have = Array(s[:window]).length
          return { added: 0, samples: have, status: :full, proxy_distrust: proxy_distrust } if have >= SENTINEL_WINDOW
          return { added: 0, samples: have, status: :no_learning, proxy_distrust: proxy_distrust } unless defined?(Learning)

          need = SENTINEL_WINDOW - have
          limit = (opts[:limit] || [need * 4, 200].max).to_i
          # Prefer scored rows; fall back to success-boolean so local hosts still warm.
          rows = Learning.outcomes(limit: limit)
          scored, unscored = rows.partition { |r| !r[:score].nil? }
          ordered = scored.reverse + unscored.reverse
          added = 0
          ordered.each do |r|
            break if added >= need

            judge = if r[:score]
                      r[:score].to_f.clamp(0.0, 1.0)
                    else
                      case r[:success]
                      when true, 'true' then 0.75
                      when 'soft' then 0.55
                      when false, 'false' then 0.25
                      else 0.5
                      end
                    end
            proxy = case r[:success]
                    when true, 'true' then true
                    when false, 'false', 'soft' then false
                    else judge >= 0.6
                    end
            record_sentinel(proxy: proxy, judge: judge)
            added += 1
          end
          final_n = Array(load_sentinel[:window]).length
          # Recompute distrust once window is full so controllers can engage.
          snap = final_n >= SENTINEL_WINDOW ? sentinel : { samples: final_n, status: :insufficient }
          {
            added: added,
            samples: final_n,
            status: (final_n >= SENTINEL_WINDOW ? :warmed_full : :warmed_partial),
            proxy_distrust: proxy_distrust,
            sentinel: snap.is_a?(Hash) ? snap.slice(:samples, :status, :reward_hacked, :proxy_distrust, :proxy, :judge) : nil
          }
        rescue StandardError => e
          { added: 0, error: "#{e.class}: #{e.message}" }
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

          if raw.include?('invalid_payload') || err.to_s.include?('invalid_payload')
            semantic = false
            shape = :invalid_payload
            err ||= 'invalid_payload'
          elsif timeout_result?(err: err, raw: raw)
            semantic = false
            shape = :timeout
            err ||= raw[/timeout after \d+s/i] || 'timeout'
          else
            semantic = ok && (exit_code.nil? || exit_code.zero? || benign)
          end
          err ||= raw[/"stderr":"([^"]{4,300})"/, 1] unless semantic
          { ok: ok, semantic_ok: semantic, exit: exit_code, err: err, benign: benign, shape: shape }
        end

        private_class_method def self.timeout_result?(opts = {})
          blob = "#{opts[:err]} #{opts[:raw]}"
          blob.match?(/timeout after \d+s/i) || blob.match?(/"error"\s*:\s*"timeout/i)
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

          # P26 — drop metric crumbs ("cap 0.2") that match loose patterns
          if defined?(Learning) && Learning.respond_to?(:checkable_claim?, true)
            return nil unless Learning.send(:checkable_claim?, claim: claim)
          elsif claim.match?(/\A(?:cap|share|proxy|judge|success|only|now|gap|score|rate)\b/i) ||
                (claim.match?(/\d+\.\d+/) && !claim.match?(/\d+\.\d+\.\d+|CVE-/i))
            return nil
          end

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

        # Trajectory-shaped chosen sides that may land DPO without prose flood.
        TRAJECTORY_SHAPES = %w[winning_trace revised_answer real_dispatch].freeze

        # P9 — write-time source quota (not only export). Prefer diverse online
        # generators over resolve-prose flood. Window is last WRITE_SOURCE_WINDOW
        # pairs; a source already above WRITE_SOURCE_CAP is refused unless
        # force: true (user_correction always forces).
        WRITE_SOURCE_CAP    = 0.40
        WRITE_SOURCE_WINDOW = 100

        # P0 — target online generator mix for W1. Gates alone cannot fill
        # an empty promote; the controller must *prefer underfilled* sources
        # (counterfactual / critic / curriculum / user_correction) when
        # resolve already dominates. Shares are soft targets, not hard caps
        # (hard cap remains WRITE_SOURCE_CAP). Trajectory-only still applies.
        TARGET_SOURCE_MIX = {
          'mistakes_resolve' => 0.30,
          'curriculum' => 0.25,
          'counterfactual' => 0.20,
          'critic' => 0.15,
          'user_correction' => 0.10
        }.freeze

        public_class_method def self.record_preference(opts = {})
          prompt   = opts[:prompt].to_s
          rejected = opts[:rejected].to_s
          chosen   = opts[:chosen].to_s
          return nil if prompt.strip.empty? || chosen.strip.empty? || rejected.strip.empty?
          return nil if chosen.strip == rejected.strip

          # Reject weak pair geometry: CORRECTION: flaw-prose is not a trajectory.
          return { skipped: :weak_pair_geometry, reason: 'chosen looks like flaw prose, not a revised answer/trace' } if chosen.match?(/\A\s*CORRECTION:\s*/i) && chosen.length < 400 && !opts[:force]

          source = (opts[:source] || :unknown).to_s
          shape  = opts[:shape].to_s
          # P25 — require trajectory shape at write time unless force / user_correction.
          # Stops resolve-prose flood from ever landing in the ledger; export scrub
          # is defense-in-depth, not the primary gate.
          traj = TRAJECTORY_SHAPES.include?(shape)
          # P25 — non-trajectory prose never lands (export scrub is defense-in-depth).
          # user_correction and explicit force: still allowed for human / migration paths.
          unless traj || opts[:force] || source == 'user_correction'
            return {
              skipped: :non_trajectory_shape,
              reason: "shape=#{shape.inspect} not in #{TRAJECTORY_SHAPES.join(',')}; pass force:true or a trajectory shape",
              source: source
            }
          end
          # P9 — write-time source quota still applies to trajectory pairs.
          # P25 made every auto-written row trajectory-shaped; if traj also
          # bypassed the quota, resolve monoculture would return via winning_trace
          # flood. Only user_correction and explicit force:true skip the cap.
          bypass_quota = opts[:force] || source == 'user_correction'
          unless bypass_quota
            quota = write_source_quota(source: source)
            return quota.merge(skipped: :source_quota) if quota[:over_cap]

            # P0 — also refuse sources the live mix already asked to suppress
            # (critic 40% vs 15% target) so write-time, not only export, rebalances.
            mix = generator_mix
            return quota.merge(skipped: :source_quota, over_cap: true, reason: "mix_suppress:#{source}") if Array(mix[:suppress]).include?(source) && mix[:n].to_i >= 10
          end

          entry = {
            id: Digest::SHA256.hexdigest("#{prompt}|#{rejected}|#{chosen}")[0, 12],
            prompt: prompt[0, 4_000],
            rejected: rejected[0, 4_000],
            chosen: chosen[0, 4_000],
            source: source,
            engine: (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s,
            timestamp: Time.now.utc.iso8601
          }
          entry[:meta] = opts[:meta] if opts[:meta].is_a?(Hash)
          entry[:shape] = opts[:shape].to_s if opts[:shape]
          FileUtils.mkdir_p(File.dirname(PREFERENCES_FILE))
          File.open(PREFERENCES_FILE, 'a') { |f| f.puts(JSON.generate(entry)) }
          entry
        end

        # Share of `source` among the newest WRITE_SOURCE_WINDOW prefs.
        public_class_method def self.write_source_quota(opts = {})
          source = opts[:source].to_s
          recent = preferences(limit: WRITE_SOURCE_WINDOW)
          return { over_cap: false, share: 0.0, n: 0, window: recent.length, underfilled: true } if recent.length < 10

          n = recent.count { |r| r[:source].to_s == source }
          share = n.to_f / recent.length
          target = TARGET_SOURCE_MIX[source]
          target_cap = target ? [WRITE_SOURCE_CAP, target + 0.05].min : WRITE_SOURCE_CAP
          {
            over_cap: share > target_cap,
            share: share.round(3),
            n: n,
            window: recent.length,
            source: source,
            cap: WRITE_SOURCE_CAP,
            target: target,
            underfilled: target ? share < (target * 0.5) : share < 0.05,
            deficit: target ? (target - share).round(3) : nil
          }
        rescue StandardError
          { over_cap: false, share: 0.0, underfilled: true }
        end

        # P0 — online generator mix report + urgency flags. Controllers
        # (auto_introspect, practice, counterfactual gate) consult this so
        # underfilled sources get scheduling priority while over-cap
        # resolve stops flooding. Returns {by_source, trajectory_fraction,
        # urgent:[], suppress:[], healthy:}.
        public_class_method def self.generator_mix(opts = {})
          limit = opts[:limit] || WRITE_SOURCE_WINDOW
          rows = preferences(limit: limit)
          usable = rows.select { |r| usable_preference?(row: r) }
          by = Hash.new(0)
          usable.each { |r| by[r[:source].to_s] += 1 }
          n = usable.length
          shares = {}
          TARGET_SOURCE_MIX.each_key { |k| shares[k] = n.zero? ? 0.0 : (by[k].to_f / n).round(3) }
          by.each_key { |k| shares[k] ||= (by[k].to_f / n).round(3) }

          traj_n = usable.count { |r| TRAJECTORY_SHAPES.include?(r[:shape].to_s) }
          traj_f = n.zero? ? 0.0 : (traj_n.to_f / n).round(3)

          urgent = []
          suppress = []
          TARGET_SOURCE_MIX.each do |src, target|
            sh = shares[src].to_f
            urgent << src if sh < (target * 0.5) && n >= 5
            suppress << src if sh > WRITE_SOURCE_CAP && n >= 10
          end
          suppress << 'mistakes_resolve' if shares['mistakes_resolve'].to_f > WRITE_SOURCE_CAP && n >= 10 && !suppress.include?('mistakes_resolve')

          healthy = urgent.empty? && suppress.empty? && traj_f >= 0.5 && n >= 10
          {
            n: n,
            raw_n: rows.length,
            by_source: by,
            shares: shares,
            targets: TARGET_SOURCE_MIX,
            trajectory_fraction: traj_f,
            urgent: urgent.uniq,
            suppress: suppress.uniq,
            healthy: healthy,
            recommendation: if healthy
                              'mix_ok'
                            elsif n < 10
                              'need_more_pairs'
                            elsif traj_f < 0.5
                              'need_trajectory_shape'
                            elsif urgent.any?
                              "boost:#{urgent.join(',')}"
                            else
                              "suppress:#{suppress.join(',')}"
                            end
          }
        rescue StandardError => e
          {
            n: 0, healthy: false, error: "#{e.class}: #{e.message}",
            urgent: %w[curriculum counterfactual critic user_correction],
            suppress: []
          }
        end

        # P0 ops — infer trajectory shape for legacy ledger rows that predate
        # P21/P25 shape tags. Used by scrub_preferences rewrite so generator_mix
        # trajectory_fraction reflects content, not missing keys.
        public_class_method def self.infer_shape(opts = {})
          r = opts.is_a?(Hash) && opts.key?(:row) ? opts[:row] : opts
          r = r.transform_keys(&:to_sym) if r.respond_to?(:transform_keys)
          existing = r[:shape].to_s
          return existing if TRAJECTORY_SHAPES.include?(existing) || existing == 'fix_prose'

          chosen = r[:chosen].to_s
          source = r[:source].to_s
          # tool-call / trace markers → winning_trace
          if chosen.match?(/\b(shell|pwn_eval|memory_|sessions_|reward_|curriculum_|extro_|mistakes_)\b/i) &&
             (chosen.include?('→') || chosen.include?('tool_call') || chosen.include?('"name"') ||
              chosen.lines.count { |l| l.strip.start_with?('{') || l.include?('arguments') } >= 1)
            return 'winning_trace'
          end
          # long revised answer from critic / user / CF → revised_answer
          return 'revised_answer' if chosen.length >= 200 && %w[critic user_correction counterfactual curriculum].include?(source)

          # counterfactual real dispatch tag in meta
          meta = r[:meta].is_a?(Hash) ? r[:meta] : {}
          return 'real_dispatch' if meta[:mode].to_s == 'real_dispatch' || meta['mode'].to_s == 'real_dispatch'

          existing.empty? ? nil : existing
        rescue StandardError
          nil
        end

        # P15 — keep only usable preference pairs for balance/export/promote.
        # Drops CORRECTION-only chosen, resolve rows without trajectory shape,
        # and chosen≪rejected unless shape is a known trajectory form.
        public_class_method def self.usable_preference?(opts = {})
          r = opts.is_a?(Hash) && opts.key?(:row) ? opts[:row] : opts
          r = r.transform_keys(&:to_sym) if r.respond_to?(:transform_keys)
          chosen = r[:chosen].to_s
          rejected = r[:rejected].to_s
          shape = r[:shape].to_s
          source = r[:source].to_s
          return false if chosen.strip.empty? || rejected.strip.empty?
          return false if chosen.strip == rejected.strip
          return false if chosen.match?(/\A\s*CORRECTION:\s*/i) && chosen.length < 400
          return false if shape == 'fix_prose'
          # P25 — resolve rows must be trajectory-shaped to count as usable
          return false if source == 'mistakes_resolve' && !TRAJECTORY_SHAPES.include?(shape)

          # chosen ≪ rejected without trajectory shape → commentary, not policy
          unless TRAJECTORY_SHAPES.include?(shape)
            return false if rejected.length >= 200 && chosen.length < (rejected.length * 0.25) && chosen.length < 200
            return false if rejected.length >= 400 && chosen.length < 120
          end
          true
        rescue StandardError
          false
        end

        # P15 — one-shot ledger hygiene. Filters in place (rewrite jsonl) or
        # report-only. Returns {before:, after:, dropped:, by_reason:, path:}.
        public_class_method def self.scrub_preferences(opts = {})
          dry = opts.key?(:dry_run) ? opts[:dry_run] : false
          path = PREFERENCES_FILE
          return { before: 0, after: 0, dropped: 0, dry_run: dry, path: path } unless File.exist?(path)

          raw = File.readlines(path)
          kept = []
          reasons = Hash.new(0)
          raw.each do |line|
            begin
              r = JSON.parse(line, symbolize_names: true)
            rescue StandardError
              reasons[:parse_error] += 1
              next
            end
            if usable_preference?(row: r)
              # P0 ops — backfill shape so trajectory_fraction is meaningful
              if r[:shape].to_s.empty?
                inferred = infer_shape(row: r)
                r = r.merge(shape: inferred) if inferred
              end
              kept << r
            else
              why = if r[:chosen].to_s.match?(/\A\s*CORRECTION:\s*/i)
                      :correction_prose
                    elsif r[:shape].to_s == 'fix_prose'
                      :fix_prose
                    elsif r[:chosen].to_s.length < (r[:rejected].to_s.length * 0.25)
                      :chosen_too_short
                    else
                      :weak_geometry
                    end
              reasons[why] += 1
            end
          end
          unless dry
            bak = "#{path}.bak-p15-#{Time.now.utc.strftime('%Y%m%d%H%M%S')}"
            FileUtils.cp(path, bak)
            File.open(path, 'w') { |f| kept.each { |r| f.puts(JSON.generate(r)) } }
          end
          {
            before: raw.length,
            after: kept.length,
            dropped: raw.length - kept.length,
            by_reason: reasons,
            dry_run: dry,
            path: path,
            backup: dry ? nil : bak
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        # P15/P5 — geometry-aware source mix. scrub:true uses usable_preference?
        # so operators see the post-hygiene diet (what export_dpo will train on).
        public_class_method def self.preference_balance(opts = {})
          limit = opts[:limit] || 10_000
          scrub = opts.key?(:scrub) ? opts[:scrub] : false
          rows = preferences(limit: limit)
          before = rows.length
          rows = rows.select { |r| usable_preference?(row: r) } if scrub
          by = Hash.new(0)
          by_shape = Hash.new(0)
          rows.each do |r|
            by[r[:source].to_s] += 1
            sh = r[:shape].to_s
            sh = 'unspecified' if sh.empty?
            by_shape[sh] += 1
          end
          total = rows.length
          frac = by.transform_values { |n| total.zero? ? 0.0 : (n.to_f / total).round(3) }
          shape_frac = by_shape.transform_values { |n| total.zero? ? 0.0 : (n.to_f / total).round(3) }
          traj_n = rows.count { |r| TRAJECTORY_SHAPES.include?(r[:shape].to_s) }
          traj_frac = total.zero? ? 0.0 : (traj_n.to_f / total).round(3)
          monoculture = total.positive? && (by.values.max.to_f / total) > 0.7
          mix = begin
            generator_mix(limit: limit)
          rescue StandardError
            nil
          end
          {
            total: before,
            kept: total,
            scrubbed: scrub,
            dropped: before - total,
            by_source: by,
            fractions: frac,
            by_shape: by_shape,
            by_shape_fraction: shape_frac,
            trajectory_fraction: traj_frac,
            monoculture: monoculture,
            generator_mix: mix,
            advice: if total < 12
                      'W1 thin: need more trajectory-shaped pairs before LoRA promote.'
                    elsif monoculture
                      'W1 monoculture: run Reward.scrub_preferences; enable :counterfactual/:critic; stop resolve-prose flood.'
                    elsif traj_frac < 0.30
                      'W1 geometry weak: <30% trajectory-shaped chosen sides — DPO would teach commentary.'
                    elsif mix && !mix[:healthy]
                      "W1 generator mix: #{mix[:recommendation]}"
                    else
                      'W1 source mix OK for gated export'
                    end
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
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
          # P15 — drop weak geometry before source-cap so resolve prose cannot
          # dominate the kept set after balance. opt-out with scrub: false.
          scrub = opts.key?(:scrub) ? opts[:scrub] : true
          geometry_dropped = 0
          if scrub
            usable = rows.select { |r| usable_preference?(row: r) }
            geometry_dropped = rows.length - usable.length
            rows = usable
          end
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
            balanced: balance, dropped: dropped, geometry_dropped: geometry_dropped,
            scrubbed: scrub, by_source: by_src,
            source_cap: balance ? (opts[:source_cap] || DPO_SOURCE_CAP).to_f : nil,
            preference_balance: begin
              preference_balance(limit: 10_000, scrub: true)
            rescue StandardError
              nil
            end
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

        # Cheap LLM ORM path. Reflect.on is gated by module_reflection (PII /
        # teacher engine). Reward still needs a judge when that is off, so we
        # call the active engine .chat directly with a short timeout. Fail
        # fast to heuristic_judge rather than a 900s Reflect hang.
        CHEAP_ORM_TIMEOUT = 12
        CHEAP_ORM_TEMP    = 0.1
        CHEAP_ORM_TRACE_N = 12
        ORM_SAMPLE_WEIGHT = 1.0
        HEURISTIC_SAMPLE_WEIGHT = 0.45
        ERROR_SAMPLE_WEIGHT = 0.15
        ENGINE_CHAT_MODS = {
          openai: 'PWN::AI::OpenAI',
          grok: 'PWN::AI::Grok',
          ollama: 'PWN::AI::Ollama',
          openwebui: 'PWN::AI::OpenWebUI',
          anthropic: 'PWN::AI::Anthropic',
          gemini: 'PWN::AI::Gemini'
        }.freeze

        # Weight a judge sample for sentinel / Learning haircuts.
        # LLM ORM counts as a full outcome; heuristic overlap is a cheap
        # prior so it cannot dominate proxy_distrust when real ORM exists.
        public_class_method def self.judge_sample_weight(opts = {})
          case opts[:source].to_s
          when 'llm_orm' then ORM_SAMPLE_WEIGHT
          when 'error' then ERROR_SAMPLE_WEIGHT
          else HEURISTIC_SAMPLE_WEIGHT
          end
        end

        private_class_method def self.llm_judge(opts = {})
          return nil unless reflect_available?

          steps = Array(opts[:trace])
          # Prefer the LAST tools — early inspect steps hide whether the
          # human got a usable result. Keep the first step for context.
          shown = compact_trace_tail(steps: steps, keep: CHEAP_ORM_TRACE_N)
          trace = shown.each_with_index.map { |s, i| "#{i + 1}. #{s.to_s.gsub(/\s+/, ' ')[0, 220]}" }.join("\n")
          req = "USER REQUEST:\n#{opts[:request].to_s[0, 700]}\n\nFINAL ANSWER:\n#{opts[:final].to_s[0, 1_600]}\n\nTOOL TRACE (#{steps.length} steps, showing #{shown.length}):\n#{trace}"
          resp = cheap_orm_chat(request: req, system_role_content: JUDGE_SYSTEM)
          parsed = parse_llm_judge(resp: resp)
          return nil if parsed.nil?

          # Soft-blend a stronger-than-overlap evidence prior so a noisy
          # cheap ORM cannot peg 0.0/1.0 against an obviously incomplete
          # or obviously complete final.
          ev = evidence_prior(request: opts[:request], final: opts[:final], trace: steps)
          if ev && ev[:confidence].to_f >= 0.5
            raw = parsed[:score].to_f
            # Sanity bounds only: do not always blend (would fight a good ORM).
            if raw >= 0.85 && ev[:score].to_f <= 0.25
              parsed[:score] = [raw, 0.45].min
              parsed[:rationale] = "#{parsed[:rationale]} | ev_cap=#{ev[:score]}"
            elsif raw <= 0.15 && ev[:score].to_f >= 0.65
              parsed[:score] = [raw, 0.45].max
              parsed[:rationale] = "#{parsed[:rationale]} | ev_floor=#{ev[:score]}"
            end
          end
          parsed
        rescue StandardError
          nil
        end

        private_class_method def self.parse_llm_judge(opts = {})
          raw = opts[:resp]
          resp = raw.is_a?(Hash) ? extract_chat_text(resp: raw) : raw.to_s
          return nil if resp.strip.empty?

          cleaned = resp.dup
          cleaned = cleaned.sub(/\A\s*```(?:json)?\s*/i, '')
          cleaned = cleaned.sub(/\s*```\s*\z/, '')
          blob = cleaned[/\{\s*"score"\s*:.*\}/m] || cleaned[/\{.*\}/m]
          return nil if blob.to_s.strip.empty?

          j = JSON.parse(blob, symbolize_names: true)
          return nil if j.nil? || !j.key?(:score)

          begin
            score = Float(j[:score])
          rescue StandardError
            return nil
          end
          score = score.clamp(0.0, 1.0)
          verdict = j[:verdict].to_s.to_sym
          verdict = if %i[solved partial wrong refused].include?(verdict)
                      verdict
                    elsif score >= 0.6
                      :solved
                    elsif score >= 0.3
                      :partial
                    else
                      :wrong
                    end
          {
            score: score,
            verdict: verdict,
            rationale: j[:rationale].to_s[0, 200],
            key_step: j[:key_step].to_i,
            source: :llm_orm
          }
        rescue StandardError
          nil
        end

        # Prefer Reflect.on (teacher engine) when module_reflection is on;
        # otherwise a bounded engine .chat. Never Loop.run.
        private_class_method def self.cheap_orm_chat(opts = {})
          req = opts[:request].to_s
          return nil if req.strip.empty?

          if reflect_on_ready?
            begin
              raw = Reflect.on(
                request: req,
                system_role_content: opts[:system_role_content],
                suppress_pii_warning: true,
                spinner: false,
                model: judge_model,
                timeout: cheap_orm_timeout,
                temp: CHEAP_ORM_TEMP,
                quiet: true
              )
              text = extract_chat_text(resp: raw)
              return text unless text.strip.empty?

              # Quiet ReadTimeout now returns nil instead of raising. That
              # empty response already spent the cheap-ORM budget — do not
              # immediately fire engine_chat_cheap (second 12s stall).
              return nil
            rescue StandardError => e
              # A 12s ReadTimeout already spent the cheap-ORM budget.
              return nil if timeout_error?(err: e)

              nil
            end
          end

          engine_chat_cheap(request: req, system_role_content: opts[:system_role_content])
        rescue StandardError
          nil
        end

        private_class_method def self.engine_chat_cheap(opts = {})
          return nil unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          eng = PWN::Env.dig(:ai, :active).to_s.downcase.to_sym
          eng = :ollama unless ENGINE_CHAT_MODS.key?(eng)
          mod_name = ENGINE_CHAT_MODS[eng]
          return nil if mod_name.to_s.empty?

          mod = begin
            Object.const_get(mod_name)
          rescue NameError
            nil
          end
          return nil unless mod && mod.respond_to?(:chat)

          chat_opts = {
            request: opts[:request],
            system_role_content: opts[:system_role_content],
            spinner: false,
            timeout: cheap_orm_timeout,
            temp: CHEAP_ORM_TEMP,
            quiet: true
          }
          model = judge_model
          chat_opts[:model] = model unless model.to_s.empty?
          extract_chat_text(resp: mod.chat(chat_opts))
        rescue StandardError
          nil
        end

        private_class_method def self.timeout_error?(opts = {})
          err = opts[:err]
          return false if err.nil?

          klass = err.class
          name = klass.name.to_s
          return true if name.include?('Timeout') || name.include?('ReadTimeout') || name.include?('OpenTimeout')
          return true if err.message.to_s.match?(/timed out reading|read timeout|open timeout/i)

          false
        rescue StandardError
          false
        end

        private_class_method def self.verifier_precedence?(opts = {})
          return true unless opts.is_a?(Hash)
          return true unless defined?(PWN::Env)

          v = PWN::Env.dig(:ai, :reward, :verifier_precedence)
          v != false
        rescue StandardError
          true
        end

        private_class_method def self.taxonomy_class(opts = {})
          given = (opts[:verdict_class] || opts['verdict_class']).to_s
          return given unless given.empty?

          vv = opts[:verifier_verdict]
          score = opts[:score].to_f
          final = opts[:final].to_s
          request = opts[:request].to_s
          return 'unverified_claim' if vv == :pass && score < 0.6
          return 'missing_artifact' if request.match?(%r{/(?:tmp|home|opt|var)/}) && !final.match?(%r{/(?:tmp|home|opt|var)/})
          return 'wrong_path' if request.include?('/tmp/') && final.include?('/tmp/') && request.split.none? { |tok| tok.start_with?('/') && final.include?(tok) }
          return 'scope_miss' if final.match?(/out of scope|SCOPE_DENY/i)
          return 'partial_coverage' if score.between?(0.3, 0.59)
          return 'style_only' if score >= 0.6 && Array(opts[:trace]).empty?

          'unverified_claim'
        end

        private_class_method def self.taxonomy_hint(opts = {})
          {
            'missing_artifact' => 'Write the requested path then read it back.',
            'wrong_path' => 'Use the absolute path named in the original request.',
            'unverified_claim' => 'Add a verifier PASS (file readback, exit 0, or hash match).',
            'scope_miss' => 'Stay inside the active engagement scope.',
            'partial_coverage' => 'Finish remaining request clauses before claiming done.',
            'style_only' => 'Produce a host-visible artifact, not prose restyling.'
          }[opts[:verdict_class].to_s] || 'Produce evidence that matches the original request.'
        end

        private_class_method def self.cheap_orm_timeout
          n = agent_flag(key: :reward_llm_timeout, default: CHEAP_ORM_TIMEOUT).to_i
          n = CHEAP_ORM_TIMEOUT if n < 2
          n = 30 if n > 30
          n
        rescue StandardError
          CHEAP_ORM_TIMEOUT
        end

        private_class_method def self.judge_model
          return nil unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)

          m = PWN::Env.dig(:ai, :agent, :model_routes, :judge)
          m = PWN::Env.dig(:ai, :agent, :reward_model) if m.to_s.empty?
          m = PWN::Env.dig(:ai, :reflect_model) if m.to_s.empty?
          m.to_s.empty? ? nil : m.to_s
        rescue StandardError
          nil
        end

        private_class_method def self.reflect_on_ready?
          return false unless defined?(Reflect)
          return false unless defined?(PWN::Env) && PWN::Env.is_a?(Hash)
          return false unless PWN::Env.dig(:ai, :module_reflection)

          Thread.current[:pwn_reflect_depth].to_i.zero?
        rescue StandardError
          false
        end

        private_class_method def self.extract_chat_text(opts = {})
          resp = opts[:resp]
          case resp
          when nil then ''
          when String then resp
          when Hash
            (
              resp[:content] || resp['content'] ||
              resp.dig(:choices, -1, :content) || resp.dig(:choices, -1, :text) ||
              resp.dig(:choices, -1, :message, :content) ||
              resp.dig('choices', -1, 'content') || resp.dig('choices', -1, 'text') ||
              resp[:reply] || resp['reply'] || resp[:final] || resp['final']
            ).to_s
          else
            resp.to_s
          end
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
          resp = cheap_orm_chat(request: req, system_role_content: PRM_SYSTEM).to_s
          resp.scan(/-?1|0/).map(&:to_i).first(opts[:trace].length)
        rescue StandardError
          nil
        end

        private_class_method def self.heuristic_judge(opts = {})
          final   = opts[:final].to_s
          request = opts[:request].to_s
          trace   = Array(opts[:trace])
          # 1.4 — empty / polite / failure-language finals cannot score high
          # just because tools mostly returned handler-ok.
          return { score: 0.0, verdict: :wrong, rationale: 'empty final', key_step: -1, source: :heuristic } if final.strip.empty?
          return { score: 0.0, verdict: :wrong, rationale: 'failure-language final', key_step: -1, source: :heuristic } if defined?(Learning) && final.match?(Learning::FAILURE_FINAL_RX)

          polite = final.match?(/\A\s*(sure|happy to help|of course|i can help|how can i|let me know)\b/i) && final.length < 120
          return { score: 0.1, verdict: :partial, rationale: 'polite non-answer', key_step: -1, source: :heuristic } if polite && trace.empty?

          ev = evidence_prior(request: request, final: final, trace: trace)
          score = ev ? ev[:score].to_f : 0.35
          # Overlap is a small on-topic gate, not the score. The evidence
          # prior (completeness, concrete claims, trace echo) is the fallback ORM.
          req_toks = request.downcase.scan(/[a-z0-9_]{3,}/).uniq
          fin_toks = final.downcase.scan(/[a-z0-9_]{3,}/).uniq
          overlap  = req_toks.empty? ? 1.0 : (req_toks & fin_toks).length.to_f / req_toks.length
          pass = final.match?(/\bPASS\b/) && !(defined?(Learning) && final.match?(Learning::FAILURE_FINAL_RX))
          long_analytical = final.length >= 800
          score = [score, 0.35].min if !pass && overlap < 0.08 && req_toks.length >= 4 && score > 0.35 && !long_analytical
          ev_score = ev ? ev[:score].to_f : 0.0
          bad   = trace.count { |t| !semantic_ok(name: 'shell', raw: t.to_s)[:semantic_ok] }
          ratio = trace.empty? ? 0.5 : 1.0 - (bad.to_f / trace.length)
          score = ((score * 0.85) + (ratio * 0.15)).round(3)
          score = [score, 0.7].max if pass
          score = [score, 0.45].min if !pass && overlap >= 0.4 && ev_score < 0.55
          score = [score, 0.45].min if ratio <= 0.15
          score = [score, 0.70].min
          score = score.round(2).clamp(0.0, 0.70)
          verdict = if score >= 0.6 then :solved
                    elsif score >= 0.3 then :partial
                    else :wrong
                    end
          rationale = "heuristic evidence=#{ev ? ev[:score] : '-'} overlap=#{overlap.round(2)} ratio=#{ratio.round(2)}"
          {
            score: score,
            verdict: verdict,
            rationale: rationale,
            key_step: -1,
            source: :heuristic,
            score_components: {
              judge: score,
              overlap: pass ? 0.0 : overlap.round(3),
              checks: 0.0,
              weights: { overlap: pass ? 0.0 : 0.15 }
            }
          }
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

        # Last-N (+ first) trace so the ORM sees the work that finished the ask.
        private_class_method def self.compact_trace_tail(opts = {})
          steps = Array(opts[:steps])
          keep = (opts[:keep] || CHEAP_ORM_TRACE_N).to_i
          return steps if steps.length <= keep

          head = [steps.first]
          tail = steps.last([keep - 1, 1].max)
          (head + tail).uniq
        end

        # Stronger-than-overlap prior: completeness, concrete claims, plan
        # coverage, failure language. Used as cheap ORM blend + heuristic fallback.
        private_class_method def self.evidence_prior(opts = {})
          final = opts[:final].to_s
          request = opts[:request].to_s
          trace = Array(opts[:trace])
          return { score: 0.0, confidence: 0.9 } if final.strip.empty?
          return { score: 0.05, confidence: 0.85 } if defined?(Learning) && Learning.const_defined?(:FAILURE_FINAL_RX) && final.match?(Learning::FAILURE_FINAL_RX)

          polite = final.match?(/\A\s*(sure|happy to help|of course|i can help|how can i|let me know)\b/i) && final.length < 120
          return { score: 0.1, confidence: 0.8 } if polite && trace.empty?

          score = 0.32
          score += 0.12 if final.length >= 160
          score += 0.10 if final.length >= 400
          concrete = final.match?(%r{\b\d+\.\d+\.\d+\.\d+(?:/\d+)?\b}) ||
                     final.match?(/\b\d+\s+hosts?\b/i) ||
                     final.match?(/\b(?:fixed|resolved|verified|pass(?:ed)?|complete)\b/i)
          short_complete = final.length.between?(12, 200) && concrete
          score -= 0.22 if final.length < 80 && !short_complete && !concrete
          score += 0.28 if short_complete || concrete
          # Truncation / mid-sentence cut is not a usable human result.
          truncated = final.length > 80 && final.match?(/[a-z,;:]$/i) && !final.match?(/[.!?]["')\]]*\s*\z/)
          score -= 0.28 if truncated
          score += 0.08 if final.match?(/\b\d+(?:\.\d+)?\b/)
          score += 0.08 if final.match?(%r{\b(?:/~|/[a-z0-9._-]+)+}i)
          score += 0.10 if final.match?(/\b(fixed|resolved|verified|rspec|rubocop|pass|complete)\b/i)
          if trace.any?
            sem_ok = trace.count { |t| semantic_ok(name: 'shell', raw: t.to_s)[:semantic_ok] }
            score += 0.08 if sem_ok.positive?
            score -= 0.12 if sem_ok.zero?
            blob = trace.join(' ')[0, 2_000].downcase
            echoed = final.downcase.scan(/[a-z0-9_]{4,}/).uniq.count { |t| blob.include?(t) }
            score += 0.08 if echoed >= 2
            score -= 0.10 if echoed.zero? && final.length > 40
          end
          req_toks = request.downcase.scan(/[a-z0-9_]{4,}/).uniq
          fin_toks = final.downcase.scan(/[a-z0-9_]{4,}/).uniq
          unless req_toks.empty?
            ov = (req_toks & fin_toks).length.to_f / req_toks.length
            score += 0.08 if ov >= 0.25
            score -= 0.12 if ov < 0.08 && req_toks.length >= 4
          end
          { score: score.round(3).clamp(0.0, 0.9), confidence: 0.62 }
        rescue StandardError
          nil
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
              if rewards[ti]
                j[:step_reward] = rewards[ti]
                # P18 — fold step_reward into Metrics so Registry.rank can bias
                fold_step_reward_to_metrics(content: j[:content], reward: rewards[ti])
              end
            end
            "#{JSON.generate(j)}\n"
          rescue StandardError
            l
          end
          File.write(path, lines.join)
        rescue StandardError
          nil
        end

        # Extract tool name from "name → …" session content and record PRM.
        private_class_method def self.fold_step_reward_to_metrics(opts = {})
          return unless defined?(Metrics) && Metrics.respond_to?(:record_step_reward)

          content = opts[:content].to_s
          name = content[/\A([a-z_][a-z0-9_]*)\s*→/i, 1] ||
                 content[/\A([a-z_][a-z0-9_]*)\s*->/i, 1] ||
                 content[/\A([a-z_][a-z0-9_]*)/, 1]
          return if name.to_s.empty?

          Metrics.record_step_reward(name: name, reward: opts[:reward])
        rescue StandardError
          nil
        end

        private_class_method def self.record_sentinel(opts = {})
          s = normalize_sentinel(raw: load_sentinel)
          # Clamp judge to [0,1] — LLM/heuristic should already, but a bad
          # write must not poison rolling means forever.
          judge = opts[:judge].to_f.clamp(0.0, 1.0)
          entry = { judge: judge, at: Time.now.utc.iso8601 }
          # P1 — optional per-sample confidence (heuristic < LLM ORM)
          entry[:confidence] = opts[:confidence].to_f.clamp(0.0, 1.0) unless opts[:confidence].nil?
          entry[:source] = opts[:source].to_s unless opts[:source].to_s.empty?
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
            h[:source] = e[:source].to_s unless e[:source].to_s.empty?
            h[:confidence] = e[:confidence].to_f.clamp(0.0, 1.0) unless e[:confidence].nil?
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

          # Blend toward LLM ORM. Once a handful of real ORM samples exist,
          # heuristic overlap is a tiny prior so proxy-judge gap tracks the
          # outcome model, not bag-of-words.
          orm_n = w.count { |e| e[:source].to_s == 'llm_orm' }
          j_num = 0.0
          j_den = 0.0
          w.each do |e|
            wt = judge_sample_weight(source: e[:source])
            wt *= 0.25 if orm_n >= 4 && e[:source].to_s != 'llm_orm'
            j_num += e[:judge].to_f * wt
            j_den += wt
          end
          judge = j_den.positive? ? (j_num / j_den) : 0.0
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
        # module_reflection gates Reflect lesson writing (PII / teacher
        # engine). Reward models still need a teacher when that is off:
        # cheap_orm_chat talks to the active engine directly. Remote engines
        # default ON so grok answers are not graded by token overlap. Local
        # ollama stays heuristic unless module_reflection or agent.reward_llm
        # is true (cost).
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
          puts "USAGE:
            # R1 — LLM Outcome Reward Model
            #{self}.judge(
              request: 'required - original user request',
              final: 'required - assistant final answer',
              session_id: 'optional - PWN::Sessions id (adds tool trace)',
              trace: 'optional - Array of tool-result strings (overrides session_id)',
              commit: 'optional - write score into learning.jsonl / sentinel (default true)',
              critic_pass: 'optional - critic pass value consumed by #judge',
              predicted: 'optional - predicted value consumed by #judge',
              proxy_ok: 'optional - proxy ok value consumed by #judge',
              persist_components: 'optional - write score_components into the learning ledger',
              verifier_verdict: 'optional - :pass when a deterministic verifier already succeeded',
              verifier_pass: 'optional - true as a boolean alias for verifier_verdict :pass'
            )

            # Run promote to success and return its result
            #{self}.promote_to_success?(
              orm: 'optional - orm value consumed by #promote_to_success?',
              verify: 'optional - verify value consumed by #promote_to_success?',
              critic: 'optional - critic value consumed by #promote_to_success?'
            )

            # Run prm and return its result
            #{self}.prm(
              request: 'required - user goal',
              session_id: 'optional - session to score in place',
              trace: 'optional - Array of {name:, args:, result:} or Strings'
            )

            # Plan-quality soft signal (W3 feature / Learning tag)
            #{self}.plan_coverage(
              plan: 'required - Array of task strings or outline text',
              final: 'required - assistant final answer',
              request: 'optional - original user request',
              trace: 'optional - Array of tool-result strings',
              session_id: 'optional - load trace from session when trace empty'
            )

            # R3 — Reward-hacking sentinel
            #{self}.sentinel

            # P4 — scalar 0.0..1.0 haircut applied to Metrics success / Registry β when
            #{self}.proxy_distrust

            # Run set proxy distrust and return its result
            #{self}.set_proxy_distrust(
              gap: 'optional - gap value consumed by #set_proxy_distrust',
              proxy: 'optional - scheme://proxy_host:port, or tor',
              judge: 'optional - judge value consumed by #set_proxy_distrust'
            )

            # Run clear proxy distrust and return its result
            #{self}.clear_proxy_distrust

            # One-shot: wipe sentinel window + distrust after deploying the
            #{self}.reset_sentinel

            # P10 — backfill the R3 ring from Learning outcomes so offline/local
            #{self}.warm_sentinel(
              limit: 'optional - limit value consumed by #warm_sentinel'
            )

            # R4 — Structured tool-result classifier
            #{self}.semantic_ok(
              name: 'required - tool name',
              raw: 'required - JSON string returned by Dispatch.call',
              args: 'optional - the tool call arguments (used for BENIGN_EXIT)'
            )

            # 2.2 — coarse recoverable shape beside the fingerprint. Paths are
            #{self}.recoverable_shape(
              err: 'optional - err value consumed by #recoverable_shape',
              stderr: 'optional - stderr value consumed by #recoverable_shape',
              exit_code: 'optional - exit code value consumed by #recoverable_shape'
            )

            # E3 — verify-as-reward (ground truth without a human)
            #{self}.verify_as_reward(
              final: 'optional - final value consumed by #verify_as_reward'
            )

            # Run record preference and return its result
            #{self}.record_preference(
              prompt: 'required - prompt value consumed by #record_preference',
              rejected: 'required - rejected value consumed by #record_preference',
              chosen: 'required - chosen value consumed by #record_preference',
              force: 'optional - force value consumed by #record_preference',
              source: 'optional - source value consumed by #record_preference (defaults to :unknown))',
              shape: 'optional - shape value consumed by #record_preference',
              meta: 'optional - meta value consumed by #record_preference'
            )

            # Share of `source` among the newest WRITE_SOURCE_WINDOW prefs
            #{self}.write_source_quota(
              source: 'optional - source value consumed by #write_source_quota'
            )

            # P0 — online generator mix report + urgency flags. Controllers
            #{self}.generator_mix(
              limit: 'optional - limit value consumed by #generator_mix (defaults to WRITE_SOURCE_WINDOW)'
            )

            # P0 ops — infer trajectory shape for legacy ledger rows that predate
            #{self}.infer_shape(
              row: 'optional - row value consumed by #infer_shape'
            )

            # P15 — keep only usable preference pairs for balance/export/promote
            #{self}.usable_preference?(
              row: 'optional - row value consumed by #usable_preference?'
            )

            # P15 — one-shot ledger hygiene. Filters in place (rewrite jsonl) or
            #{self}.scrub_preferences(
              dry_run: 'optional - dry run value consumed by #scrub_preferences'
            )

            # P15/P5 — geometry-aware source mix. scrub:true uses usable_preference?
            #{self}.preference_balance(
              limit: 'optional - limit value consumed by #preference_balance (defaults to 10_000)',
              scrub: 'optional - scrub value consumed by #preference_balance'
            )

            # Run preferences and return its result
            #{self}.preferences(
              limit: 'optional - limit value consumed by #preferences (defaults to 500)',
              source: 'required - source value consumed by #preferences'
            )

            # Run export dpo and return its result
            #{self}.export_dpo(
              format: 'optional - format value consumed by #export_dpo (defaults to :dpo))',
              out: 'optional - out value consumed by #export_dpo',
              scrub: 'optional - scrub value consumed by #export_dpo',
              balance: 'optional - balance value consumed by #export_dpo',
              source_cap: 'optional - source cap value consumed by #export_dpo'
            )

            # Run reset and return its result
            #{self}.reset

            # Weight a judge sample for sentinel / Learning haircuts
            #{self}.judge_sample_weight(
              source: 'optional - source value consumed by #judge_sample_weight'
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
