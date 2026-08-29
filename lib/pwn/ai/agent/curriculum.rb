# frozen_string_literal: true

require 'json'
require 'fileutils'
require 'time'
require 'open3'

module PWN
  module AI
    module Agent
      # PWN::AI::Agent::Curriculum is Tier 4/5 of the pwn-ai reinforcement
      # loop — the SELF-PLAY layer that turns the agent from a passive
      # experience-recorder into an active learner:
      #
      #   S1  .practice        — Mistake-driven auto-curriculum. Reads
      #                          Mistakes.top(unresolved), asks Reflect to
      #                          generate 3 minimal reproducer prompts per
      #                          signature, self-plays each under Loop.run,
      #                          and auto-mistakes_resolve when Reward.judge
      #                          says the practice run solved it. THE AGENT
      #                          PRACTISES ITS OWN WEAKNESSES OVERNIGHT.
      #   S2  .counterfactual  — On a repeated in-turn failure, forks: branch
      #                          A continues with the correction_hint, branch
      #                          B asks an alt persona for a different tool.
      #                          Reward.judge picks the winner; (loser,
      #                          winner) → Reward.record_preference. Real
      #                          advantage estimation, not imagined rollouts.
      #   S3  .critic          — Constitutional critic persona with TOOL
      #                          ACCESS (can shell/extro_verify the claim).
      #                          Runs BEFORE note_outcome; its verdict feeds
      #                          Reward.judge and its concrete flaw becomes a
      #                          preference pair when the agent self-corrects.
      #   S4  .red_team_plan   — After plan_first, an adversarial persona
      #                          reviews the plan against THIS host's
      #                          Metrics/Mistakes/extro_drift and injects a
      #                          pre-emptive correction_hint on the step it
      #                          predicts will fail.
      #   C3  .hindsight       — Hindsight Experience Replay. On failure,
      #                          asks the judge "what DID this trajectory
      #                          accomplish?", relabels the episode with the
      #                          achieved-goal as success:true. Free positive
      #                          samples from failures — first HER on real
      #                          tool traces.
      #   W2  .train_and_gate  — export_finetune + export_dpo → local LoRA
      #                          (unsloth/axolotl if installed) → replay
      #                          Mistakes.top on vN vs vN+1 → promote iff
      #                          resolved(N+1) > resolved(N). Fully autonomous
      #                          weight-level self-improvement with a
      #                          regression gate.
      #   W3  .calibrate       — Tracks plan_first predicted p(success) vs
      #                          actual outcome → Brier score in Metrics.
      #
      # All entry points are cron-safe (never raise into the caller) and
      # depth-guarded via Swarm's Thread.current[:pwn_swarm_depth] so a
      # curriculum run cannot recurse into itself.
      module Curriculum
        CURRICULUM_DIR = File.join(Dir.home, '.pwn', 'curriculum')
        MODELS_FILE    = File.join(CURRICULUM_DIR, 'models.json')
        CRITIC_NAME    = 'pwn_critic'
        RED_TEAM_NAME  = 'pwn_red_team'
        ALT_NAME       = 'pwn_alt'

        # ----------------------------------------------------------------
        # S1 — Mistake-driven auto-curriculum
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # report = PWN::AI::Agent::Curriculum.practice(
        #   limit: 'optional - top-N unresolved mistakes to practise (default 3)',
        #   prompts_per: 'optional - reproducer prompts per mistake (default 2)',
        #   dry_run: 'optional - generate prompts but do not self-play (default false)'
        # )

        # Priority-fix 1 — N-night cooldown window for thrashing signatures
        # and stale "needs_human" tags. Signatures that score ~0 for
        # COOLDOWN_FAIL_NIGHTS consecutive practice nights are parked so
        # the curriculum stops burning cycles on them.
        COOLDOWN_FAIL_NIGHTS = 3
        COOLDOWN_FILE = File.join(CURRICULUM_DIR, 'cooldown.json')

        public_class_method def self.practice(opts = {})
          limit   = (opts[:limit] || 3).to_i
          per     = (opts[:prompts_per] || 2).to_i
          dry_run = opts[:dry_run] ? true : false
          return { skipped: 'recursion guard' } if in_curriculum?

          FileUtils.mkdir_p(CURRICULUM_DIR)
          # 2.4 / 2.5 / P1 — skip reward_signal + needs_code_change / parked
          # + cooldown thrash + needs_human. Over-fetch so filters still fill.
          fetch_n = [limit * 4, 12].max
          candidates = if defined?(Mistakes)
                         Mistakes.top(limit: fetch_n, unresolved_only: true, practiceable_only: true)
                       else
                         []
                       end
          cool = load_cooldown
          candidates = candidates.sort_by { |m| -m[:count].to_i }
          targets = candidates.reject { |m| practice_skip?(mistake: m, cooldown: cool) }.first(limit)
          results = []

          with_curriculum_guard do
            targets.each do |m|
              next if practice_skip?(mistake: m, cooldown: cool)

              prompts = generate_reproducers(mistake: m, count: [per, 2].max)
              runs = dry_run ? [] : prompts.map { |p| self_play(prompt: p, tag: "practice:#{m[:signature]}") }
              solved = runs.select { |r| r[:score].to_f >= 0.6 }
              mean = runs.empty? ? 0.0 : (runs.sum { |r| r[:score].to_f } / runs.length)
              resolved = false
              # 2.4 — auto-resolve only with N≥2 holdout successes + store trace
              # P23 — auto-resolve only with N≥2 holdouts at judge≥0.7 AND a
              # real tool trace (not empty-final luck). Budget fingerprints
              # additionally require mean holdout ≥0.7 and short-horizon tags.
              if solved.length >= 2 && defined?(Mistakes)
                best = solved.max_by { |r| r[:score] }
                winning = best[:trace].to_s.strip
                winning = best[:final].to_s.strip if winning.length < 20
                budgetish = %w[agent_loop assistant_answer].include?(m[:tool].to_s) ||
                            m[:error].to_s.downcase.include?('budget')
                # refuse resolve on budget targets when winning_trace is prose-only
                trace_ok = winning.length >= 20 && (
                  !budgetish || winning.match?(/→|shell|pwn_eval|tool/i) || best[:final].to_s.length.between?(1, 800)
                )
                poc_ok = if budgetish || %w[agent_loop assistant_answer].include?(m[:tool].to_s)
                           practice_poc_ok?(run: best)
                         else
                           true
                         end
                unless trace_ok && poc_ok
                  bump_cooldown!(cooldown: cool, signature: m[:signature], mean: mean) unless dry_run
                  results << {
                    signature: m[:signature], tool: m[:tool], prompts: prompts,
                    runs: runs.map { |r| { score: r[:score], verdict: r[:verdict] } },
                    resolved: false, mean_score: mean.round(3),
                    reason: 'holdouts_ok_but_trace_weak'
                  }
                  next
                end
                fix = best[:final].to_s.lines.first(3).join.strip[0, 400]
                Mistakes.resolve(
                  signature: m[:signature],
                  fix: "auto-curriculum: #{fix}",
                  structured: {
                    strategy: budgetish ? 'short_horizon_finish' : 'curriculum_practice',
                    tool: m[:tool],
                    holdout_tests: solved.map { |r| r[:prompt] || r[:request] }.compact.first(5),
                    winning_trace: winning[0, 2_000]
                  }
                )
                # P14 — trajectory-shaped curriculum pair (not first-3-lines fix prose).
                # Mistakes.resolve also lands a mistakes_resolve pair via winning_trace;
                # this :curriculum row keeps W1 source diversity honest.
                if defined?(Reward)
                  rejected = m[:snippet].to_s
                  rejected = "FAILING: tool=#{m[:tool]} err=#{m[:error]}" if rejected.strip.empty?
                  chosen = if best[:trace].to_s.strip.length >= 20
                             parts = []
                             parts << "STRATEGY: curriculum_practice | #{m[:tool]}"
                             parts << "WINNING_TRACE:\n#{best[:trace].to_s[0, 3_000]}"
                             parts << "FINAL:\n#{best[:final].to_s[0, 800]}" unless best[:final].to_s.strip.empty?
                             parts.join("\n")
                           else
                             best[:final].to_s[0, 3_500]
                           end
                  Reward.record_preference(
                    prompt: (best[:prompt] || prompts.first).to_s,
                    rejected: rejected[0, 2_000],
                    chosen: chosen,
                    source: :curriculum,
                    shape: :winning_trace,
                    meta: {
                      signature: m[:signature],
                      score: best[:score],
                      holdouts: solved.length
                    }
                  )
                end
                resolved = true
                cool.delete(m[:signature].to_s)
              elsif !dry_run
                # P1 — track zero-progress nights; park after COOLDOWN_FAIL_NIGHTS
                bump_cooldown!(cooldown: cool, signature: m[:signature], mean: mean)
              end
              results << {
                signature: m[:signature], tool: m[:tool], prompts: prompts,
                runs: runs.map { |r| { score: r[:score], verdict: r[:verdict] } },
                resolved: resolved, mean_score: mean.round(3)
              }
            end
          end
          save_cooldown(cooldown: cool)
          log(event: :practice, data: results)
          kpi = practice_kpi(results: results)
          {
            practiced: results.length,
            resolved: results.count { |r| r[:resolved] },
            skipped_cooldown: cool.count { |_, v| v[:fail_nights].to_i >= COOLDOWN_FAIL_NIGHTS },
            skipped_parked: (defined?(Mistakes) && Mistakes.respond_to?(:operator_inbox) ? Mistakes.operator_inbox[:count] : 0),
            operator_inbox: (defined?(Mistakes) && Mistakes.respond_to?(:operator_inbox) ? Mistakes.operator_inbox[:items] : []),
            results: results,
            dry_run: dry_run,
            kpi: kpi,
            generator_mix: (defined?(Reward) && Reward.respond_to?(:generator_mix) ? Reward.generator_mix : nil)
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        # Priority-fix 3 — Offline ORM/PRM pass over recent sessions so
        # local :failure_only introspect does not starve the reward corpus.
        # Cron this nightly. Never raises.
        #
        # Supported Method Parameters::
        # r = PWN::AI::Agent::Curriculum.offline_judge(
        #   since_hours: 'optional - lookback window (default 24)',
        #   limit: 'optional - max sessions to score (default 40)',
        #   prm: 'optional - also run Process Reward Model (default true)',
        #   commit: 'optional - write scores into learning/sentinel (default true)'
        # )

        public_class_method def self.offline_judge(opts = {})
          return { skipped: 'no Sessions' } unless defined?(PWN::Sessions)
          return { skipped: 'no Reward' } unless defined?(Reward)

          since_h = (opts[:since_hours] || 24).to_i
          limit   = (opts[:limit] || 40).to_i
          do_prm  = opts.key?(:prm) ? opts[:prm] : true
          commit  = opts.key?(:commit) ? opts[:commit] : true
          cutoff  = Time.now.utc - (since_h * 3_600)

          # PWN::Sessions.list is arity-0 (no kwargs). Cap/sort after the call.
          sids = if PWN::Sessions.respond_to?(:list)
                   Array(PWN::Sessions.list)
                     .sort_by { |s| s.is_a?(Hash) ? s[:mtime].to_s : '' }
                     .reverse
                     .first(limit * 2)
                     .map { |s| s.is_a?(Hash) ? (s[:id] || s[:session_id] || s['id'] || s['session_id']) : s.to_s }
                 else
                   dir = (PWN::Sessions::SESSIONS_DIR if defined?(PWN::Sessions::SESSIONS_DIR)) || File.join(Dir.home, '.pwn', 'sessions')
                   Dir[File.join(dir, '*.jsonl')].sort_by { |f| -File.mtime(f).to_i }.first(limit * 2).map { |f| File.basename(f, '.jsonl') }
                 end

          scored = []
          sids.first(limit * 3).each do |sid|
            break if scored.length >= limit

            t = begin
              PWN::Sessions.load(session_id: sid)
            rescue StandardError
              []
            end
            next if t.nil? || t.empty?

            mtime = begin
              path = File.join(
                (PWN::Sessions::SESSIONS_DIR if defined?(PWN::Sessions::SESSIONS_DIR)) || File.join(Dir.home, '.pwn', 'sessions'),
                "#{sid}.jsonl"
              )
              File.exist?(path) ? File.mtime(path).utc : nil
            rescue StandardError
              nil
            end
            next if mtime && mtime < cutoff

            if commit && defined?(Learning)
              prior = Learning.outcomes(limit: 500).find do |o|
                o[:session_id].to_s == sid.to_s && o[:score] && Array(o[:tags]).include?('offline_judge')
              end
              next if prior
            end

            user = t.reverse.find { |e| e[:role].to_s == 'user' }
            final = t.reverse.find { |e| e[:role].to_s == 'assistant' && !e[:content].to_s.start_with?('PLAN:') }
            next unless user && final

            req = user[:content].to_s
            fin = final[:content].to_s
            next if req.strip.empty? || fin.strip.empty?

            v = Reward.judge(request: req, final: fin, session_id: sid, commit: commit)
            Reward.prm(request: req, session_id: sid) if do_prm
            # P7/W3 — offline path must also fill calibration so the controller
            # (force plan_first/critic at n≥8) actually becomes reachable under
            # :failure_only local introspect. Pull p(success)= out of any PLAN.
            if commit
              plan = t.find { |e| e[:role].to_s == 'assistant' && e[:content].to_s.start_with?('PLAN:') }
              pred = plan && plan[:content].to_s[/p\(success\)\s*=\s*([01](?:\.\d+)?)/i, 1]
              if pred
                eng = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env))
                calibrate(predicted: pred.to_f, actual: v[:score].to_f, engine: eng)
              end
            end
            if commit && defined?(Learning)
              # P29 — keep verdict tag score-aligned (same as auto_introspect).
              sc = v[:score].to_f
              verd = if defined?(Learning) && Learning.respond_to?(:verdict_for_score, true)
                       Learning.send(:verdict_for_score, score: sc).to_s
                     elsif sc >= 0.6 then 'solved'
                     elsif sc >= 0.3 then 'partial'
                     else 'wrong'
                     end
              Learning.note_outcome(
                task: req[0, 120],
                success: sc >= 0.6,
                score: sc,
                details: "offline_judge #{verd}(#{sc.round(2)}) #{v[:rationale]}",
                session_id: sid,
                tags: ['offline_judge', 'auto', verd],
                judge_source: v[:source]
              )
            end
            scored << { session_id: sid, score: v[:score], verdict: v[:verdict] }
          end

          mean = scored.empty? ? nil : (scored.sum { |r| r[:score].to_f } / scored.length).round(3)
          # P10 — keep R3 window warm so proxy_distrust can engage on local hosts
          warm = (Reward.warm_sentinel(limit: 120) if commit && defined?(Reward) && Reward.respond_to?(:warm_sentinel))
          # P0 ops — nightly ledger hygiene so generator_mix success criteria can
          # fire: drop prose flood, backfill missing shapes, then snapshot mix+KPI.
          scrub = nil
          mix = nil
          kpi = nil
          if commit && defined?(Reward)
            scrub = Reward.scrub_preferences(dry_run: false) if Reward.respond_to?(:scrub_preferences)
            mix = Reward.generator_mix if Reward.respond_to?(:generator_mix)
          end
          rec = { reclassified: 0 }
          rec = reclassify_backlog if commit && respond_to?(:reclassify_backlog)
          kpi = practice_kpi(results: [], reclassified_n: rec[:reclassified]) if commit && respond_to?(:practice_kpi)
          out = {
            scored: scored.length, mean: mean, since_hours: since_h,
            results: scored.first(10), sentinel_warm: warm,
            scrub: scrub, generator_mix: mix, practice_kpi: kpi
          }
          log(event: :offline_judge, data: out.except(:results))
          out
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        # P5 — W1 diversity report so monoculture is visible before DPO export.

        public_class_method def self.preference_balance(opts = {})
          return { total: 0 } unless defined?(Reward)

          # P15 — prefer Reward.preference_balance (geometry-aware + optional scrub).
          if Reward.respond_to?(:preference_balance)
            return Reward.preference_balance(
              limit: opts[:limit] || 10_000,
              scrub: opts.key?(:scrub) ? opts[:scrub] : false
            )
          end

          rows = Reward.preferences(limit: opts[:limit] || 10_000)
          by = Hash.new(0)
          rows.each { |r| by[r[:source].to_s] += 1 }
          total = rows.length
          frac = by.transform_values { |n| total.zero? ? 0.0 : (n.to_f / total).round(3) }
          monoculture = total.positive? && (by.values.max.to_f / total) > 0.7
          {
            total: total,
            by_source: by,
            fractions: frac,
            monoculture: monoculture,
            advice: if monoculture
                      'W1 monoculture: enable :counterfactual/:critic or loosen S2 gates; DPO will overfit mistakes_resolve prose.'
                    else
                      'W1 source mix OK'
                    end
          }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        public_class_method def self.counterfactual(opts = {})
          # P0 — when generator_mix marks counterfactual underfilled, run even
          # if the auto-flag would keep it off (remote-default still respected
          # only when mix is healthy). Still refuse recursion.
          mix_need = begin
            m = defined?(Reward) && Reward.respond_to?(:generator_mix) ? Reward.generator_mix : {}
            Array(m[:urgent]).include?('counterfactual')
          rescue StandardError
            false
          end
          return nil unless enabled?(key: :counterfactual) || mix_need || opts[:force]
          return nil if in_curriculum?

          request = opts[:request].to_s
          ensure_persona(name: ALT_NAME, role: 'You are an alternative-approach generator for pwn-ai. Given a failing tool call, propose ONE concrete DIFFERENT tool + args that would achieve the same sub-goal on this host. Reply with the tool call only, no prose.')

          branch_a = opts[:hint].to_s.strip
          branch_a = "retry #{opts[:name]} with corrected args" if branch_a.empty?
          branch_b = with_curriculum_guard do
            ask_persona(name: ALT_NAME, request: "Goal: #{request[0, 300]}\nFailing: #{opts[:name]}(#{opts[:args].to_s[0, 200]}) → #{opts[:error].to_s[0, 200]}\nPropose ONE different tool+args.")
          end
          return nil if branch_b.to_s.strip.empty?

          sa_h = score_branch_detailed(request: request, branch: branch_a)
          sb_h = score_branch_detailed(request: request, branch: branch_b)
          sa = sa_h[:score]
          sb = sb_h[:score]
          if sb > sa
            winner = branch_b
            loser = branch_a
            tag = :b
            wmeta = sb_h
          else
            winner = branch_a
            loser = branch_b
            tag = :a
            wmeta = sa_h
          end
          real_hit = sa_h[:mode] == :real_dispatch || sb_h[:mode] == :real_dispatch
          shape = real_hit ? :real_dispatch : :imagined
          if defined?(Reward)
            Reward.record_preference(
              prompt: "#{request} | failing: #{opts[:name]} → #{opts[:error]}",
              rejected: loser.to_s[0, 2_000],
              chosen: winner.to_s[0, 2_000],
              source: :counterfactual,
              shape: shape,
              meta: {
                a_score: sa, b_score: sb,
                a_mode: sa_h[:mode], b_mode: sb_h[:mode],
                winner_trace: wmeta[:trace].to_s[0, 500]
              }
            )
          end
          log(event: :counterfactual, data: { branch: tag, a: sa, b: sb, tool: opts[:name].to_s, shape: shape })
          { branch: tag, content: winner, score: [sa, sb].max, a: sa, b: sb, shape: shape, a_mode: sa_h[:mode], b_mode: sb_h[:mode] }
        rescue StandardError => e
          warn "[pwn-ai/curriculum] counterfactual swallowed: #{e.class}: #{e.message}"
          nil
        end

        # ----------------------------------------------------------------
        # S3 — Constitutional critic (with tool access)
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # v = PWN::AI::Agent::Curriculum.critic(
        #   request: 'required - user request',
        #   final: 'required - candidate final answer',
        #   session_id: 'optional - for evidence lookup'
        # )
        #
        # Returns { verdict: :pass|:flaw, flaw:, confidence: }. On :flaw the
        # (final, flaw) pair is recorded as a preference so a future
        # self-correction becomes DPO signal.

        public_class_method def self.critic(opts = {})
          mix_need = begin
            m = defined?(Reward) && Reward.respond_to?(:generator_mix) ? Reward.generator_mix : {}
            Array(m[:urgent]).include?('critic')
          rescue StandardError
            false
          end
          return { verdict: :pass, source: :disabled } unless enabled?(key: :critic) || opts[:text_only] || mix_need || opts[:force]
          return { verdict: :pass, source: :recursion } if in_curriculum?

          # P24 — text_only: single Reflect shot, no tool-armed persona swarm.
          # Used when budget_exhaustion_hot? so critic cannot thrash the budget
          # that auto_introspect is trying to protect.
          return critic_text_only(request: opts[:request], final: opts[:final], session_id: opts[:session_id]) if opts[:text_only]

          ensure_persona(name: CRITIC_NAME, role: "You are pwn-ai's constitutional critic. Given a REQUEST and a candidate ANSWER, find ONE concrete, verifiable flaw (wrong fact, missing step, unsupported claim, broken command). You MAY call shell / extro_verify / pwn_eval to check. If none found reply exactly: PASS. Otherwise reply: FLAW: <one line>.")
          reply = with_curriculum_guard do
            ask_persona(name: CRITIC_NAME, request: "REQUEST:\n#{opts[:request].to_s[0, 800]}\n\nANSWER:\n#{opts[:final].to_s[0, 2_000]}")
          end
          if reply.to_s.strip.upcase.start_with?('PASS')
            log(event: :critic, data: { verdict: :pass })
            { verdict: :pass, confidence: 0.7 }
          else
            flaw = reply.to_s.sub(/\AFLAW:\s*/i, '').strip[0, 300]
            Mistakes.record(tool: 'assistant_answer', error: "critic: #{flaw}", args: opts[:final].to_s[0, 200], session_id: opts[:session_id], source: :model) if defined?(Mistakes)
            # P9 — DPO pair geometry: rejected=bad final, chosen=REVISED full
            # answer (not "CORRECTION: flaw" prose). Prefer persona rewrite.
            if defined?(Reward) && !flaw.to_s.empty?
              revised = revise_after_flaw(
                request: opts[:request],
                final: opts[:final],
                flaw: flaw,
                session_id: opts[:session_id]
              )
              Reward.record_preference(
                prompt: opts[:request].to_s[0, 1_000],
                rejected: opts[:final].to_s[0, 2_000],
                chosen: revised,
                source: :critic,
                shape: :revised_answer,
                meta: { flaw: flaw.to_s[0, 200] }
              )
            end
            log(event: :critic, data: { verdict: :flaw, flaw: flaw.to_s[0, 200] })
            { verdict: :flaw, flaw: flaw, confidence: 0.7 }
          end
        rescue StandardError => e
          { verdict: :pass, error: e.message }
        end

        # ----------------------------------------------------------------
        # S4 — Adversarial plan review (grounded in telemetry)
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # hint = PWN::AI::Agent::Curriculum.red_team_plan(
        #   request: 'required - user goal',
        #   plan: 'required - numbered plan text from plan_first'
        # )

        public_class_method def self.red_team_plan(opts = {})
          return nil unless enabled?(key: :red_team_plan)
          return nil if in_curriculum?

          # P17 — never nest a red-team persona loop when budget_exhaustion
          # fingerprints dominate open mistakes (amplifier of agent_loop ×N).
          begin
            if defined?(Loop) && Loop.respond_to?(:budget_exhaustion_hot?, true) &&
               Loop.send(:budget_exhaustion_hot?)
              return nil
            end
          rescue StandardError
            # fall through
          end

          ensure_persona(name: RED_TEAM_NAME, role: 'You are pwn-ai\'s adversarial plan reviewer. Given a numbered tool plan and telemetry from THIS host (tool success rates, known mistakes, environment drift), identify the ONE step most likely to fail and say why in ≤2 lines. Cite the metric/mistake/drift. If the plan is sound reply: SOUND.')
          telemetry = build_telemetry
          reply = with_curriculum_guard do
            ask_persona(name: RED_TEAM_NAME, request: "GOAL: #{opts[:request].to_s[0, 300]}\n\nPLAN:\n#{opts[:plan].to_s[0, 1_200]}\n\nHOST TELEMETRY:\n#{telemetry}", text_only: true)
          end
          return nil if reply.to_s.strip.upcase.start_with?('SOUND') || reply.to_s.strip.empty?

          "[pwn-ai/red_team] pre-emptive: #{reply.to_s.strip[0, 400]}"
        rescue StandardError => e
          warn "[pwn-ai/curriculum] red_team_plan swallowed: #{e.class}: #{e.message}"
          nil
        end

        # ----------------------------------------------------------------
        # C3 — Hindsight Experience Replay
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # PWN::AI::Agent::Curriculum.hindsight(
        #   request: 'required - the FAILED goal',
        #   final: 'required - the final produced anyway',
        #   session_id: 'required - trajectory to relabel'
        # )

        public_class_method def self.hindsight(opts = {})
          return nil unless enabled?(key: :hindsight, default: true)
          return nil unless reflect_available?

          req = "The agent FAILED at: #{opts[:request].to_s[0, 300]}\nBut it produced: #{opts[:final].to_s[0, 800]}\n\nIn ≤12 words, what goal DID this trajectory accomplish? Reply with the goal only, or NOTHING if truly nothing."
          achieved = Reflect.on(request: req, suppress_pii_warning: true).to_s.strip
          return nil if achieved.empty? || achieved.upcase == 'NOTHING' || achieved.length > 200

          Learning.note_outcome(task: achieved, success: 'soft', details: "HER-relabelled from failed: #{opts[:request].to_s[0, 100]}", session_id: opts[:session_id], tags: %w[hindsight her soft], score: 0.7) if defined?(Learning)
          { original: opts[:request].to_s[0, 100], achieved: achieved }
        rescue StandardError
          nil
        end

        # ----------------------------------------------------------------
        # W2 — Online LoRA A/B with regression gate
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # r = PWN::AI::Agent::Curriculum.train_and_gate(
        #   base_model: 'optional - ollama base tag (default PWN::Env[:ai][:ollama][:model])',
        #   trainer: 'optional - :unsloth | :axolotl | :auto (default :auto)',
        #   dry_run: 'optional - export + build eval set but do not train (default true)'
        # )
        #
        # Best-effort orchestrator. When a supported trainer is installed it
        # produces ~/.pwn/finetune/pwn-vN/, cuts an ollama Modelfile with the
        # LoRA adapter, then REPLAYS Mistakes.top against vN and vN+1 under
        # Reward.judge. Promotes (writes MODELS_FILE) iff vN+1 resolves more
        # signatures. When no trainer is present it still exports SFT+DPO and
        # emits the exact CLI to run manually — so the pipeline is complete
        # even on a box without GPU.

        public_class_method def self.train_and_gate(opts = {})
          dry_run = if opts.key?(:dry_run)
                      opts[:dry_run]
                    else
                      mix = defined?(Reward) && Reward.respond_to?(:generator_mix) ? Reward.generator_mix : {}
                      healthy = mix.is_a?(Hash) && mix[:healthy] == true
                      cal_ok = defined?(Metrics) && Metrics.respond_to?(:calibration_green?) && Metrics.calibration_green?
                      !(healthy && cal_ok)
                    end
          FileUtils.mkdir_p(CURRICULUM_DIR)
          sft = defined?(Learning) ? Learning.export_finetune(format: :sharegpt) : nil
          dpo = defined?(Reward) ? Reward.export_dpo : nil
          evalset = build_eval_set

          state = load_models
          version = state[:current].to_i + 1
          base = opts[:base_model] || (PWN::Env.dig(:ai, :ollama, :model) if defined?(PWN::Env)) || 'llama3'
          trainer = detect_trainer(preference: opts[:trainer])

          result = {
            version: version, base: base, trainer: trainer,
            sft: sft, dpo: dpo, eval_prompts: evalset.length, dry_run: dry_run
          }

          if dry_run || trainer.nil?
            result[:export_only] = true
            result[:weight_loop] = :export_ready
            result[:advice] = if trainer.nil?
                                'No trainer found — weight loop is EXPORT-ONLY on this host. ' \
                                  'Install unsloth or axolotl on a GPU box, then re-run with dry_run:false. ' \
                                  "Datasets ready at #{sft&.[](:path)} + #{dpo&.[](:path)}."
                              else
                                'dry_run — datasets + eval set exported; pass dry_run:false to train+gate+promote.'
                              end
            result[:manual_cli] = manual_train_cli(base: base, sft: sft, dpo: dpo, version: version)
            # P5 — surface W1 monoculture beside the export so operators see it
            result[:preference_balance] = begin
              preference_balance
            rescue StandardError
              nil
            end
            log(event: :train_and_gate, data: result)
            return result
          end

          adapter = run_trainer(trainer: trainer, base: base, sft: sft, dpo: dpo, version: version)
          return result.merge(error: 'trainer produced no adapter') unless adapter

          candidate = ollama_create(base: base, adapter: adapter, version: version)
          baseline  = state[:tag] || base
          # P11 — gate v2: resolved delta + mean judge + frozen smoke set.
          gate = ab_gate_v2(baseline: baseline, candidate: candidate, evalset: evalset)
          # P19 — refuse promote when W1 diet is still prose/monoculture.
          # Export-only is correct until scrubbed pairs show trajectory diversity.
          diet = preference_diet_gate
          gate = gate.merge(preference_diet: diet)
          promoted = gate[:promote] == true && diet[:ok] == true
          gate[:promote] = promoted
          gate[:promote_blocked_by_diet] = true unless diet[:ok]
          if promoted
            state[:previous] = state[:tag]
            state[:tag] = candidate
            state[:current] = version
            state[:promoted_at] = Time.now.utc.iso8601
            state[:gate] = gate
            save_models(state: state)
          end
          result.merge(adapter: adapter, candidate: candidate, gate: gate, promoted: promoted, weight_loop: :closed)
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        # ----------------------------------------------------------------
        # W3 — Calibration head
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # PWN::AI::Agent::Curriculum.calibrate(predicted:, actual:, engine:)

        # ----------------------------------------------------------------
        # P1 — Outer curriculum KPI: does practice cut live [REPEATING]?
        # ----------------------------------------------------------------
        # Snapshot unresolved repeating counts before/after practice nights
        # into ~/.pwn/curriculum_kpi.jsonl so week-over-week delta is visible
        # without scraping Mistakes by hand. practice() always appends a row.

        KPI_FILE = File.join(Dir.home, '.pwn', 'curriculum_kpi.jsonl')

        public_class_method def self.reclassify_backlog(opts = {})
          rows = defined?(Mistakes) ? Mistakes.top(limit: opts[:limit] || 80, unresolved_only: true) : []
          inbox = if defined?(Mistakes) && Mistakes.respond_to?(:operator_inbox)
                    Array(Mistakes.operator_inbox(limit: 80)[:items] || Mistakes.operator_inbox(limit: 80)[:rows])
                  else
                    []
                  end
          counts = { fixable_by_agent: 0, needs_code_change: 0, wontfix_obsolete: 0, reclassified: 0 }
          now = Time.now.utc
          (rows + inbox).uniq { |m| m[:signature] }.each do |m|
            next unless m.is_a?(Hash)

            err = m[:error].to_s
            age_d = begin
              (now - Time.parse(m[:last_seen].to_s)) / 86_400.0
            rescue StandardError
              0.0
            end
            obsolete = err.match?(/PATH=|utf-8|invalid byte|generator/i) || (age_d > 7 && m[:count].to_i <= 1)
            if obsolete || (m[:parked] && age_d > 7)
              Mistakes.park(signature: m[:signature], reason: 'wontfix_obsolete') if defined?(Mistakes) && Mistakes.respond_to?(:park)
              counts[:wontfix_obsolete] += 1
              counts[:reclassified] += 1
            elsif m[:needs_code_change]
              counts[:needs_code_change] += 1
            else
              counts[:fixable_by_agent] += 1
            end
          end
          counts
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        public_class_method def self.practice_kpi(opts = {})
          results = Array(opts[:results])
          top = defined?(Mistakes) ? Mistakes.top(limit: 50, unresolved_only: true) : []
          repeating = top.select { |m| m[:count].to_i >= 3 }
          budgetish = repeating.count do |m|
            t = m[:tool].to_s
            e = m[:error].to_s.downcase
            t == 'agent_loop' || t == 'assistant_answer' ||
              e.include?('budget') || e.include?('iteration budget')
          end
          row = {
            at: Time.now.utc.iso8601,
            unresolved_total: top.length,
            repeating_n: repeating.length,
            repeating_sum_count: repeating.sum { |m| m[:count].to_i },
            budget_repeating_n: budgetish,
            practiced: results.length,
            resolved_tonight: results.count { |r| r[:resolved] },
            reclassified_n: (opts[:reclassified_n] || 0).to_i,
            mean_holdout: begin
              hold = results.map { |r| r[:mean_score] || r[:score] }.compact
              hold = Learning.outcomes(limit: 20).filter_map { |o| o[:score] } if hold.empty? && defined?(Learning)
              hold.empty? ? 0.0 : (hold.sum(&:to_f) / hold.length).round(3)
            end
          }
          begin
            FileUtils.mkdir_p(File.dirname(KPI_FILE))
            File.open(KPI_FILE, 'a') { |f| f.puts(JSON.generate(row)) }
          rescue StandardError
            nil
          end
          trend = repeating_trend
          row.merge(trend: trend)
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        # Week-over-week (or last-N snapshots) delta on repeating_n.
        # Positive delta_repeating = getting worse; negative = practice working.
        public_class_method def self.repeating_trend(opts = {})
          limit = (opts[:limit] || 14).to_i
          return { samples: 0, delta_repeating: nil, status: :no_data } unless File.exist?(KPI_FILE)

          rows = File.readlines(KPI_FILE).last(limit).filter_map do |l|
            JSON.parse(l, symbolize_names: true)
          rescue StandardError
            nil
          end
          return { samples: 0, delta_repeating: nil, status: :no_data } if rows.empty?
          return { samples: rows.length, delta_repeating: 0, status: :baseline, latest: rows.last } if rows.length < 2

          first = rows.first
          last = rows.last
          d_rep = last[:repeating_n].to_i - first[:repeating_n].to_i
          d_budget = last[:budget_repeating_n].to_i - first[:budget_repeating_n].to_i
          status = if d_rep <= -2 then :improving
                   elsif d_rep >= 2 then :regressing
                   else :flat
                   end
          {
            samples: rows.length,
            from: first[:at],
            to: last[:at],
            delta_repeating: d_rep,
            delta_budget_repeating: d_budget,
            latest_repeating_n: last[:repeating_n],
            status: status
          }
        rescue StandardError => e
          { samples: 0, status: :error, error: "#{e.class}: #{e.message}" }
        end

        public_class_method def self.calibrate(opts = {})
          p = (opts.key?(:predicted) && !opts[:predicted].nil? ? opts[:predicted] : 0.5).to_f.clamp(0.0, 1.0)
          a = opts[:actual].to_f.clamp(0.0, 1.0)
          brier = (p - a)**2
          Metrics.record_calibration(predicted: p, actual: a, brier: brier, engine: opts[:engine]) if defined?(Metrics) && Metrics.respond_to?(:record_calibration)
          { predicted: p, actual: a, brier: brier.round(4) }
        end

        # ----------------------------------------------------------------
        # privates
        # ----------------------------------------------------------------

        # P24 — single-shot text critic (no tools, no persona Loop.run).
        private_class_method def self.critic_text_only(opts = {})
          req = opts[:request].to_s
          final = opts[:final].to_s
          return { verdict: :pass, source: :text_only_empty } if final.strip.empty?

          reply = if reflect_available?
                    Reflect.on(
                      request: "You are a strict critic. Given REQUEST and ANSWER, reply PASS or FLAW: <one line>.\nREQUEST:\n#{req[0, 600]}\nANSWER:\n#{final[0, 1_200]}",
                      suppress_pii_warning: true
                    ).to_s
                  else
                    # heuristic fallback: empty / self-reported failure / budget stop
                    if final.match?(/\[pwn-ai\].*budget|iteration budget exhausted|i (was )?unable to|failed to\b/i)
                      'FLAW: answer reports failure or budget exhaustion'
                    else
                      'PASS'
                    end
                  end
          if reply.to_s.strip.upcase.start_with?('PASS')
            { verdict: :pass, source: :text_only, confidence: 0.55 }
          else
            flaw = reply.to_s.sub(/\AFLAW:\s*/i, '').strip[0, 300]
            # Do NOT Mistakes.record assistant_answer thrash from text_only path —
            # that was feeding the budget-exhaustion mistake pile.
            { verdict: :flaw, flaw: flaw, source: :text_only, confidence: 0.55 }
          end
        rescue StandardError => e
          { verdict: :pass, source: :text_only_error, error: e.message }
        end

        # P9 — turn a critic flaw into a DPO-chosen REVISED answer (trajectory
        # shaped), not "CORRECTION: <flaw>" commentary. Best-effort: ask Reflect
        # to rewrite; fall back to a structured scaffold that still contains the
        # original answer + the concrete fix.
        private_class_method def self.revise_after_flaw(opts = {})
          req = opts[:request].to_s
          final = opts[:final].to_s
          flaw = opts[:flaw].to_s
          revised = nil
          if reflect_available?
            prompt = <<~P
              Revise the ANSWER so it no longer has this flaw. Return the FULL
              corrected answer only (no preamble, no "CORRECTION:" prefix).
              REQUEST: #{req[0, 600]}
              FLAW: #{flaw[0, 300]}
              ANSWER: #{final[0, 1_500]}
            P
            revised = Reflect.on(request: prompt, suppress_pii_warning: true).to_s.strip
          end
          if revised.to_s.strip.empty? || revised.strip == final.strip || revised.match?(/\A\s*CORRECTION:/i)
            revised = <<~REV.strip
              REVISED ANSWER (addresses: #{flaw[0, 180]}):
              #{final[0, 1_200]}

              Fix applied: #{flaw[0, 300]}
              Do not repeat the flawed claim or step above; prefer verified evidence from tools.
            REV
          end
          revised.to_s[0, 4_000]
        rescue StandardError
          "REVISED ANSWER (addresses: #{opts[:flaw].to_s[0, 180]}):\n#{opts[:final].to_s[0, 1_200]}"
        end

        private_class_method def self.generate_reproducers(opts = {})
          m = opts[:mistake]
          count = (opts[:count] || 2).to_i
          count = 2 if count < 1
          # P1 — natural user tasks, NEVER "reproduce mistake SIG: …" dumps.
          # Those teach the model to parrot fingerprints, not to avoid them.
          natural_fallback = natural_repro_prompts(mistake: m, count: count)
          if reflect_available?
            req = <<~REQ
              Generate #{count} NATURAL pwn-ai user tasks (one per line, ≤18 words) a human would actually type.
              Each task should EXERCISE the skill underlying this past failure so the agent practises the CORRECT approach.
              Do NOT mention signatures, mistake ids, exit codes, JSON envelopes, or the word "reproduce".
                tool: #{m[:tool]}
                failure_shape: #{m[:shape] || 'unknown'}
                error_summary: #{m[:error].to_s[0, 120]}
                sample_args: #{m[:sample_args].to_s[0, 120]}
                known_fix_hint: #{m[:fix].to_s[0, 160]}
              Output ONLY the tasks, one per line.
            REQ
            resp = Reflect.on(request: req, suppress_pii_warning: true).to_s
            lines = resp.lines
                        .map { |l| l.gsub(/^\s*[-*\d.)]+\s*/, '').strip }
                        .reject(&:empty?)
                        .grep_v(/reproduce mistake|signature\s+[a-f0-9]{8,}|step_reward/i)
                        .first(count)
            return lines if lines.length >= count

            natural_fallback.each { |p| lines << p unless lines.include?(p) }
            return lines.first(count)
          end
          natural_fallback
        end

        # Domain-aware natural prompts when Reflect is off or returns junk.
        private_class_method def self.natural_repro_prompts(opts = {})
          m = opts[:mistake]
          n = (opts[:count] || 2).to_i
          tool = m[:tool].to_s
          shape = m[:shape].to_s
          err = m[:error].to_s.downcase
          pool = case tool
                 when 'shell'
                   if shape == 'enoent' || err.include?('no such file')
                     [
                       'List files under /opt/pwn/lib and show the first ruby file path',
                       'Check whether /tmp exists then print its permissions',
                       'Find README.md under /opt/pwn without failing if missing',
                       'Show the cwd and confirm /etc/passwd is readable'
                     ]
                   elsif shape == 'syntax' || err.include?('syntax error')
                     [
                       'Run a safe one-liner that prints hello from ruby -e',
                       'Count lines in /etc/hosts using wc -l',
                       'Show kernel release with uname -r',
                       'Print the first 3 lines of /etc/os-release'
                     ]
                   elsif shape == 'nonzero_exit' || err.include?('"exit"')
                     [
                       'Search /opt/pwn for the string semantic_ok with ripgrep',
                       'Diff /etc/hosts against itself and summarise the result',
                       'Test whether the command false is present then continue',
                       'Find files named "*.md" under /opt/pwn/documentation'
                     ]
                   elsif err.include?('auth') || err.include?('github')
                     [
                       'Check git remote -v inside /opt/pwn without pushing',
                       'Report whether gh auth status is logged in',
                       'Show git log -1 --oneline in /opt/pwn',
                       'List git branches without network calls'
                     ]
                   else
                     [
                       'Print the hostname and current user',
                       'Show free disk space on / with df -h',
                       'List listening TCP ports with ss -lnt',
                       'Display the active ruby version'
                     ]
                   end
                 when 'pwn_eval'
                   [
                     'Evaluate 1 + 1 via the pwn REPL and return the value',
                     'Ask pwn_eval for PWN::Version and report it',
                     'Use pwn_eval to list PWN::AI::Agent constants',
                     'Return Dir.pwd from pwn_eval'
                   ]
                 when 'agent_loop', 'assistant_answer'
                   [
                     'Write a working PoC to /tmp/pwn-practice-poc.txt that proves the issue, then stop',
                     'Save a chained-impact PoC under /tmp/pwn-practice-chain.txt with reproduction steps',
                     'Use pwn_eval to call PWN::Reports::JSON.generate with a findings hash to /tmp/pwn-practice-findings.json',
                     'Produce evidence-backed severity in /tmp/pwn-practice-sev.md including a PoC path'
                   ]
                 else
                   if err.include?('budget exhausted') || err.include?('iteration budget') ||
                      (err.include?('handler_error') && err.include?('budget'))
                     [
                       'Answer in one shell call: print kernel release with uname -r',
                       'In at most two tools, show cwd and ruby version then stop',
                       'Give a final answer with no tools: what is 7 times 8?',
                       'Finish under three iterations: list /tmp and report file count'
                     ]
                   else
                     [
                       "Demonstrate a correct use of the #{tool} tool on this host",
                       "Use #{tool} to answer a simple factual question about this system",
                       "Show a minimal successful #{tool} call with valid arguments",
                       "Recover from a bad #{tool} invocation without retrying the same args"
                     ]
                   end
                 end
          Array.new(n) { |i| pool[i % pool.length] }
        end

        private_class_method def self.practice_skip?(opts = {})
          m = opts[:mistake]
          return true if m.nil?
          return true if m[:tool].to_s == 'reward_signal'
          return true if m[:needs_code_change] || m[:parked]
          return true if m[:needs_human]
          return true if m[:source].to_s == 'reward_signal'

          cool = opts[:cooldown] || {}
          entry = cool[m[:signature].to_s] || cool[m[:signature].to_sym]
          return true if entry && entry[:fail_nights].to_i >= COOLDOWN_FAIL_NIGHTS && (entry[:parked] || entry['parked'])

          false
        end

        private_class_method def self.bump_cooldown!(opts = {})
          cool = opts[:cooldown]
          sig  = opts[:signature].to_s
          mean = opts[:mean].to_f
          e = cool[sig] ||= { 'fail_nights' => 0, 'last_mean' => 1.0 }
          # coerce keys to strings for JSON round-trip stability
          e = e.transform_keys(&:to_s)
          if mean < 0.15
            e['fail_nights'] = e['fail_nights'].to_i + 1
          else
            e['fail_nights'] = [e['fail_nights'].to_i - 1, 0].max
          end
          e['last_mean'] = mean
          e['last_at'] = Time.now.utc.iso8601
          if e['fail_nights'].to_i >= COOLDOWN_FAIL_NIGHTS
            e['parked'] = true
            if defined?(Mistakes) && Mistakes.respond_to?(:park)
              begin
                Mistakes.park(
                  signature: sig,
                  reason: "curriculum cooldown: mean_score≈#{mean.round(2)} for #{e['fail_nights']} nights — needs_human"
                )
              rescue StandardError
                nil
              end
            end
          end
          cool[sig] = e
        end

        private_class_method def self.load_cooldown
          return {} unless File.exist?(COOLDOWN_FILE)

          JSON.parse(File.read(COOLDOWN_FILE))
        rescue StandardError
          {}
        end

        private_class_method def self.save_cooldown(opts = {})
          FileUtils.mkdir_p(CURRICULUM_DIR)
          File.write(COOLDOWN_FILE, JSON.pretty_generate(opts[:cooldown] || {}))
        rescue StandardError
          nil
        end

        private_class_method def self.self_play(opts = {})
          sid = PWN::Sessions.create(title: "curriculum #{opts[:tag]}")[:id]
          # P23 — short-horizon graded tasks: cap iters so practice actually
          # teaches finish-under-N instead of letting DEFAULT_MAX_ITERS mask it.
          prompt = opts[:prompt].to_s
          short = prompt.match?(/\b(one shell|at most two|no tools|three iterations|finish under|do not explore|short plan)\b/i)
          prev_max = :__unset__
          capped = false
          if short && defined?(PWN::Env) && PWN::Env.is_a?(Hash) && PWN::Env[:ai].is_a?(Hash) && PWN::Env[:ai][:agent].is_a?(Hash) && !PWN::Env[:ai][:agent].frozen?
            prev_max = PWN::Env[:ai][:agent].key?(:max_iters) ? PWN::Env[:ai][:agent][:max_iters] : :__unset__
            PWN::Env[:ai][:agent][:max_iters] = 15
            capped = true
          end
          begin
            final = Loop.run(request: prompt, session_id: sid)
          ensure
            if capped && defined?(PWN::Env) && PWN::Env[:ai].is_a?(Hash) && PWN::Env[:ai][:agent].is_a?(Hash) && !PWN::Env[:ai][:agent].frozen?
              if prev_max == :__unset__
                PWN::Env[:ai][:agent].delete(:max_iters)
              else
                PWN::Env[:ai][:agent][:max_iters] = prev_max
              end
            end
          end
          v = Reward.judge(request: prompt, final: final, session_id: sid, commit: false)
          # 2.4 — capture tool trace for structured_fix.winning_trace
          trace = begin
            if defined?(PWN::Sessions)
              PWN::Sessions.load(session_id: sid)
                           .select { |e| e[:role].to_s == 'tool' }
                           .map { |e| e[:content].to_s[0, 400] }
                           .join("\n")[0, 2_000]
            end
          rescue StandardError
            nil
          end
          { session_id: sid, prompt: opts[:prompt], final: final, score: v[:score], verdict: v[:verdict], trace: trace }
        rescue StandardError => e
          { prompt: opts[:prompt], error: e.message, score: 0.0, trace: nil }
        end

        private_class_method def self.score_branch(opts = {})
          score_branch_detailed(**opts)[:score]
        end

        # Returns {score:, mode: :real_dispatch|:imagined|:default, trace:}.
        # Callers that need honest advantage estimation should inspect :mode.
        private_class_method def self.score_branch_detailed(opts = {})
          branch = opts[:branch].to_s
          request = opts[:request].to_s
          real = try_real_dispatch_score(branch: branch)
          return { score: real, mode: :real_dispatch, trace: branch.to_s[0, 500] } if real

          return { score: 0.5, mode: :default, trace: nil } unless reflect_available?

          req = "Goal: #{request}\nProposed next action: #{branch}\nOn a scale 0.0-1.0, how likely is this to advance the goal on a Kali Linux host? Reply with ONLY the number."
          imagined = Reflect.on(request: req, suppress_pii_warning: true).to_s[/[01](?:\.\d+)?/].to_f.clamp(0.0, 1.0)
          # haircut imagined scores so they never outrank a real dispatch
          { score: (imagined * 0.6).clamp(0.0, 0.6), mode: :imagined, trace: nil }
        rescue StandardError
          { score: 0.5, mode: :default, trace: nil }
        end

        # Best-effort: if branch names a registered tool + args, run ONE Dispatch
        # and score via Reward.semantic_ok / short judge — real advantage.
        private_class_method def self.try_real_dispatch_score(opts = {})
          branch = opts[:branch].to_s
          # patterns: "shell({"command":"..."})" or JSON {"name":"shell","arguments":{...}}
          name = branch[/\b([a-z_][a-z0-9_]{2,})\s*\(/i, 1]
          args = branch[/\((\{.*\})\)/m, 1]
          if name.nil?
            begin
              j = JSON.parse(branch[/\{.*\}/m].to_s, symbolize_names: true)
              name = (j[:name] || j.dig(:function, :name)).to_s
              args = j[:arguments] || j[:args] || j.dig(:function, :arguments)
            rescue StandardError
              return nil
            end
          end
          return nil if name.to_s.empty?
          return nil unless defined?(Registry) && defined?(Dispatch)

          Registry.discover
          return nil unless Registry.lookup(name: name)

          tc = {
            id: "cf_#{Process.pid}_#{rand(1000)}",
            type: 'function',
            function: { name: name, arguments: args.is_a?(String) ? args : JSON.generate(args || {}) }
          }
          raw = Dispatch.call(tool_call: tc)
          sem = defined?(Reward) ? Reward.semantic_ok(name: name, raw: raw.to_s, args: args) : { semantic_ok: raw.to_s.include?('"success":true') }
          sem[:semantic_ok] ? 0.85 : 0.15
        rescue StandardError
          nil
        end

        private_class_method def self.practice_poc_ok?(opts = {})
          run = opts[:run] || {}
          blob = "#{run[:final]}\n#{run[:trace]}\n#{run[:prompt]}"
          paths = blob.scan(%r{(/tmp/[A-Za-z0-9._+-]+)})
          paths.flatten.any? { |path| File.file?(path) && File.size(path).positive? }
        rescue StandardError
          false
        end

        private_class_method def self.ask_persona(opts = {})
          return nil unless defined?(Swarm)

          r = Swarm.ask(name: opts[:name], request: opts[:request], text_only: opts[:text_only])
          r.is_a?(Hash) ? r[:reply].to_s : r.to_s
        rescue StandardError
          nil
        end

        private_class_method def self.ensure_persona(opts = {})
          return unless defined?(Swarm)
          return if Swarm.personas.key?(opts[:name].to_sym)

          Swarm.spawn(name: opts[:name], role: opts[:role], toolsets: %w[terminal pwn extrospection], max_iters: 24)
        rescue StandardError
          nil
        end

        private_class_method def self.build_telemetry
          parts = []
          parts << Metrics.to_context(limit: 5).to_s.strip if defined?(Metrics)
          parts << Mistakes.to_context(limit: 4).to_s.strip if defined?(Mistakes)
          if defined?(Extrospection)
            d = Extrospection.drift(live: false)
            parts << "DRIFT: #{Array(d[:changed]).first(3).map { |c| c[:path] }.join(', ')}" unless Array(d[:changed]).empty?
          end
          parts.reject(&:empty?).join("\n")
        rescue StandardError
          ''
        end

        private_class_method def self.build_eval_set
          rows = if defined?(Mistakes)
                   Mistakes.top(limit: 40, unresolved_only: false).reject do |m|
                     m[:parked] || m[:needs_code_change] || m[:needs_human]
                   end.first(20)
                 else
                   []
                 end
          rows.map { |m| { signature: m[:signature], prompt: generate_reproducers(mistake: m, count: 1).first } }
        end

        private_class_method def self.ab_gate(opts = {})
          evalset  = opts[:evalset]
          baseline = replay_on(tag: opts[:baseline], evalset: evalset)
          candid   = replay_on(tag: opts[:candidate], evalset: evalset)
          { baseline: opts[:baseline], candidate: opts[:candidate], baseline_resolved: baseline, candidate_resolved: candid, evalset_size: evalset.length }
        end

        # P11 — promote only when candidate beats baseline on (a) resolved count
        # with margin, (b) mean judge score, and (c) no smoke regression. Smoke
        # set is fixed natural tasks, not Mistakes.top, so eval-set memorisation
        # cannot self-promote.
        private_class_method def self.ab_gate_v2(opts = {})
          evalset  = Array(opts[:evalset])
          baseline = replay_on_detailed(tag: opts[:baseline], evalset: evalset)
          candid   = replay_on_detailed(tag: opts[:candidate], evalset: evalset)
          smoke    = smoke_eval_set
          base_smoke = replay_on_detailed(tag: opts[:baseline], evalset: smoke)
          cand_smoke = replay_on_detailed(tag: opts[:candidate], evalset: smoke)

          b_res = baseline[:resolved].to_i
          c_res = candid[:resolved].to_i
          n     = [evalset.length, 1].max
          delta = c_res - b_res
          rel   = delta.to_f / n
          resolved_win = delta >= 1 && (n < 10 || rel >= 0.05)

          b_mean = baseline[:mean_score].to_f
          c_mean = candid[:mean_score].to_f
          mean_win = c_mean + 1e-9 >= b_mean

          smoke_ok = cand_smoke[:resolved].to_i >= base_smoke[:resolved].to_i &&
                     cand_smoke[:mean_score].to_f + 0.05 >= base_smoke[:mean_score].to_f

          promote = resolved_win && mean_win && smoke_ok
          {
            baseline: opts[:baseline],
            candidate: opts[:candidate],
            baseline_resolved: b_res,
            candidate_resolved: c_res,
            baseline_mean: b_mean.round(3),
            candidate_mean: c_mean.round(3),
            delta_resolved: delta,
            relative_delta: rel.round(3),
            smoke: {
              baseline_resolved: base_smoke[:resolved],
              candidate_resolved: cand_smoke[:resolved],
              baseline_mean: base_smoke[:mean_score],
              candidate_mean: cand_smoke[:mean_score]
            },
            resolved_win: resolved_win,
            mean_win: mean_win,
            smoke_ok: smoke_ok,
            promote: promote,
            evalset_size: evalset.length,
            gate_version: 2
          }
        end

        private_class_method def self.smoke_eval_set
          [
            { signature: 'smoke_uname', prompt: 'Print the kernel release with uname -r' },
            { signature: 'smoke_pwd',   prompt: 'Show the current working directory' },
            { signature: 'smoke_ruby',  prompt: 'Display the active ruby version' }
          ]
        end

        # P19 — weight promote requires scrubbed trajectory diversity, not just
        # A/B eval win. export_ready remains the correct posture otherwise.
        private_class_method def self.preference_diet_gate(opts = {})
          return { ok: false, reason: 'no Reward' } unless defined?(Reward)

          bal = if Reward.respond_to?(:preference_balance)
                  Reward.preference_balance(limit: opts[:limit] || 10_000, scrub: true)
                else
                  preference_balance(limit: opts[:limit] || 10_000)
                end
          total = bal[:kept].to_i
          total = bal[:total].to_i if total <= 0
          return { ok: false, reason: 'too_few_pairs', total: total, min: 12 } if total < 12

          frac = bal[:fractions] || {}
          max_share = frac.values.map(&:to_f).max || 1.0
          traj_frac = bal[:trajectory_fraction].to_f
          ok = !bal[:monoculture] && max_share <= 0.45 && traj_frac >= 0.5
          {
            ok: ok,
            total: total,
            monoculture: bal[:monoculture],
            max_source_share: max_share.round(3),
            trajectory_fraction: traj_frac.round(3),
            by_source: bal[:by_source],
            reason: ok ? 'diet_ok' : 'need_trajectory_diversity_or_rebalance'
          }
        rescue StandardError => e
          { ok: false, reason: "#{e.class}: #{e.message}" }
        end

        private_class_method def self.replay_on_detailed(opts = {})
          tag = opts[:tag].to_s
          return { resolved: 0, mean_score: 0.0, scores: [] } if tag.empty?

          scores = []
          with_ollama_model(tag: tag) do
            Array(opts[:evalset]).each do |e|
              r = self_play(prompt: e[:prompt], tag: "gate:#{tag}")
              scores << r[:score].to_f
            end
          end
          resolved = scores.count { |s| s >= 0.7 }
          mean = scores.empty? ? 0.0 : (scores.sum / scores.length)
          { resolved: resolved, mean_score: mean.round(3), scores: scores }
        rescue StandardError
          { resolved: 0, mean_score: 0.0, scores: [] }
        end

        private_class_method def self.replay_on(opts = {})
          tag = opts[:tag].to_s
          return 0 if tag.empty?

          with_ollama_model(tag: tag) do
            opts[:evalset].count do |e|
              r = self_play(prompt: e[:prompt], tag: "gate:#{tag}")
              r[:score].to_f >= 0.7
            end
          end
        rescue StandardError
          0
        end

        private_class_method def self.with_ollama_model(opts = {})
          ai = defined?(PWN::Env) ? PWN::Env[:ai] : nil
          return yield unless ai.is_a?(Hash) && ai[:ollama].is_a?(Hash) && !ai[:ollama].frozen?

          prev_model  = ai[:ollama][:model]
          prev_active = ai[:active]
          ai[:ollama][:model] = opts[:tag]
          ai[:active] = 'ollama'
          begin
            yield
          ensure
            ai[:ollama][:model] = prev_model
            ai[:active] = prev_active
          end
        end

        # W2 trainer discovery/execution is pure Ruby filesystem + argv spawn.
        # Never shell-out via backticks or shell-string Open3 for probe/install
        # checks. unsloth/axolotl presence is inferred from PATH CLIs and
        # site-packages layout; any external process uses argv arrays only.

        TRAINER_CLI = {
          unsloth: %w[unsloth],
          axolotl: %w[axolotl]
        }.freeze

        TRAINER_MODULE_HINTS = {
          unsloth: %w[unsloth/__init__.py unsloth/models/__init__.py],
          axolotl: %w[axolotl/__init__.py axolotl/cli/train.py]
        }.freeze

        private_class_method def self.detect_trainer(opts = {})
          pref = opts[:preference].to_s.downcase
          pref = '' if pref.empty? || pref == 'auto'
          return pref.to_sym if %w[unsloth axolotl].include?(pref) && trainer_installed?(name: pref)

          %w[unsloth axolotl].find { |t| trainer_installed?(name: t) }&.to_sym
        end

        private_class_method def self.trainer_installed?(opts = {})
          name = opts[:name].to_s.downcase.to_sym
          return false unless TRAINER_CLI.key?(name)

          return true if trainer_cli_path(name: name)
          return true if trainer_module_path(name: name)

          false
        rescue StandardError
          false
        end

        private_class_method def self.trainer_cli_path(opts = {})
          name = opts[:name].to_s.downcase.to_sym
          Array(TRAINER_CLI[name]).each do |bin|
            path = which_bin(name: bin)
            return path if path
          end
          nil
        end

        private_class_method def self.trainer_module_path(opts = {})
          name = opts[:name].to_s.downcase.to_sym
          hints = TRAINER_MODULE_HINTS[name] || []
          python_site_package_roots.each do |root|
            hints.each do |rel|
              candidate = File.join(root, rel)
              return File.dirname(candidate) if File.file?(candidate)
            end
            # bare package dir with any .py content counts as installed
            pkg = File.join(root, name.to_s)
            return pkg if Dir.exist?(pkg) && !Dir.glob(File.join(pkg, '**', '*.py')).empty?
          end
          nil
        end

        private_class_method def self.python_site_package_roots
          roots = []
          # User + system prefixes commonly used by pip/venv/conda
          [
            File.join(Dir.home, '.local', 'lib'),
            '/usr/lib',
            '/usr/local/lib',
            File.join(Dir.home, 'miniconda3', 'lib'),
            File.join(Dir.home, 'anaconda3', 'lib'),
            File.join(Dir.home, 'mambaforge', 'lib'),
            File.join(Dir.home, 'miniforge3', 'lib')
          ].each do |base|
            next unless Dir.exist?(base)

            Dir.glob(File.join(base, 'python*', 'site-packages')).each { |d| roots << d if Dir.exist?(d) }
            Dir.glob(File.join(base, 'python*', 'dist-packages')).each { |d| roots << d if Dir.exist?(d) }
          end
          # Active virtualenv / conda env if advertised
          if (prefix = ENV['VIRTUAL_ENV'] || ENV.fetch('CONDA_PREFIX', nil))
            Dir.glob(File.join(prefix, 'lib', 'python*', 'site-packages')).each { |d| roots << d if Dir.exist?(d) }
          end
          # PYTHONPATH entries
          ENV.fetch('PYTHONPATH', '').split(File::PATH_SEPARATOR).each do |p|
            roots << p if !p.empty? && Dir.exist?(p)
          end
          roots.uniq
        end

        private_class_method def self.which_bin(opts = {})
          name = opts[:name].to_s
          return nil if name.empty?
          # Absolute path shortcut
          return name if name.include?(File::SEPARATOR) && File.executable?(name) && !File.directory?(name)

          ENV.fetch('PATH', '').split(File::PATH_SEPARATOR).each do |dir|
            next if dir.empty?

            path = File.join(dir, name)
            return path if File.executable?(path) && !File.directory?(path)
          end
          nil
        end

        private_class_method def self.run_trainer(opts = {})
          trainer = opts[:trainer].to_s.downcase.to_sym
          out_dir = File.join(DPO_DIR_CONST, "pwn-v#{opts[:version]}")
          FileUtils.mkdir_p(out_dir)
          adapter = File.join(out_dir, 'adapter')
          FileUtils.mkdir_p(adapter)

          ok = case trainer
               when :axolotl
                 run_axolotl_trainer(
                   base: opts[:base],
                   sft: opts[:sft],
                   dpo: opts[:dpo],
                   out_dir: out_dir,
                   adapter: adapter
                 )
               when :unsloth
                 run_unsloth_trainer(
                   base: opts[:base],
                   sft: opts[:sft],
                   dpo: opts[:dpo],
                   out_dir: out_dir,
                   adapter: adapter
                 )
               else
                 false
               end

          return nil unless ok
          return adapter if Dir.exist?(adapter)

          nil
        rescue StandardError
          nil
        end

        # Axolotl exposes a real CLI — invoke it with argv Open3 (no shell).
        private_class_method def self.run_axolotl_trainer(opts = {})
          bin = trainer_cli_path(name: :axolotl)
          return false unless bin

          sft_path = opts.dig(:sft, :path) || opts[:sft]
          cfg = File.join(opts[:out_dir], 'axolotl.yml')
          File.write(cfg, axolotl_config(base: opts[:base], sft: sft_path, out: opts[:adapter]))
          _o, e, s = Open3.capture3(bin, 'train', cfg)
          warn "[pwn-ai/curriculum] axolotl: #{e.to_s[0, 400]}" unless s.success?
          s.success?
        rescue StandardError => e
          warn "[pwn-ai/curriculum] axolotl: #{e.class}: #{e.message}"
          false
        end

        # Unsloth is a Python library (no first-class CLI). We still orchestrate
        # from Ruby: write the driver script with File.write, locate an
        # interpreter via PATH (File.executable?), and spawn argv-only.
        private_class_method def self.run_unsloth_trainer(opts = {})
          py = which_bin(name: 'python3') || which_bin(name: 'python')
          return false unless py
          return false unless trainer_installed?(name: :unsloth)

          sft_path = opts.dig(:sft, :path) || opts[:sft]
          dpo_path = opts.dig(:dpo, :path) || opts[:dpo]
          script = File.join(opts[:out_dir], 'train.py')
          File.write(
            script,
            unsloth_script(base: opts[:base], sft: sft_path, dpo: dpo_path, out: opts[:out_dir])
          )
          _o, e, s = Open3.capture3(py, script)
          warn "[pwn-ai/curriculum] unsloth: #{e.to_s[0, 400]}" unless s.success?
          s.success?
        rescue StandardError => e
          warn "[pwn-ai/curriculum] unsloth: #{e.class}: #{e.message}"
          false
        end

        private_class_method def self.axolotl_config(opts = {})
          <<~YAML
            base_model: #{opts[:base]}
            model_type: AutoModelForCausalLM
            tokenizer_type: AutoTokenizer
            load_in_4bit: true
            datasets:
              - path: #{opts[:sft]}
                type: sharegpt
                conversation: conversations
            dataset_prepared_path: last_run_prepared
            output_dir: #{opts[:out]}
            adapter: lora
            lora_r: 16
            lora_alpha: 16
            sequence_len: 4096
            sample_packing: false
            val_set_size: 0.0
            num_epochs: 1
            micro_batch_size: 1
            gradient_accumulation_steps: 4
            learning_rate: 0.0002
            bf16: auto
            tf32: false
            gradient_checkpointing: true
            logging_steps: 1
            save_steps: 100
            warmup_steps: 0
            evals_per_epoch: 0
            saves_per_epoch: 1
          YAML
        end

        private_class_method def self.ollama_create(opts = {})
          tag = "pwn-v#{opts[:version]}"
          modelfile = File.join(File.dirname(opts[:adapter]), 'Modelfile')
          File.write(modelfile, "FROM #{opts[:base]}\nADAPTER #{opts[:adapter]}\n")
          bin = which_bin(name: 'ollama')
          if bin
            # argv form — no shell redirection / interpolation
            _o, _e, _s = Open3.capture3(bin, 'create', tag, '-f', modelfile)
          end
          tag
        end

        private_class_method def self.manual_train_cli(opts = {})
          [
            "# SFT: axolotl train --base_model #{opts[:base]} --dataset #{opts[:sft]&.[](:path)} --output_dir ~/.pwn/finetune/pwn-v#{opts[:version]}",
            "# DPO: python -m trl.dpo --model #{opts[:base]} --dataset #{opts[:dpo]&.[](:path)} --output ~/.pwn/finetune/pwn-v#{opts[:version]}/adapter",
            "# ollama create pwn-v#{opts[:version]} -f ~/.pwn/finetune/pwn-v#{opts[:version]}/Modelfile"
          ]
        end

        private_class_method def self.unsloth_script(opts = {})
          <<~PY
            # auto-generated by PWN::AI::Agent::Curriculum.train_and_gate
            from unsloth import FastLanguageModel
            from datasets import load_dataset
            from trl import SFTTrainer, DPOTrainer
            model, tok = FastLanguageModel.from_pretrained("#{opts[:base]}", load_in_4bit=True)
            model = FastLanguageModel.get_peft_model(model, r=16, lora_alpha=16)
            sft = load_dataset("json", data_files="#{opts[:sft]}")["train"]
            SFTTrainer(model=model, tokenizer=tok, train_dataset=sft, dataset_text_field="conversations", max_seq_length=4096).train()
            dpo = load_dataset("json", data_files="#{opts[:dpo]}")["train"]
            DPOTrainer(model=model, tokenizer=tok, train_dataset=dpo, beta=0.1).train()
            model.save_pretrained("#{opts[:out]}/adapter")
          PY
        end

        DPO_DIR_CONST = File.join(Dir.home, '.pwn', 'finetune')

        private_class_method def self.load_models
          return { current: 0 } unless File.exist?(MODELS_FILE)

          JSON.parse(File.read(MODELS_FILE), symbolize_names: true)
        rescue StandardError
          { current: 0 }
        end

        private_class_method def self.save_models(opts = {})
          FileUtils.mkdir_p(CURRICULUM_DIR)
          File.write(MODELS_FILE, JSON.pretty_generate(opts[:state]))
        end

        private_class_method def self.log(opts = {})
          FileUtils.mkdir_p(CURRICULUM_DIR)
          File.open(File.join(CURRICULUM_DIR, 'log.jsonl'), 'a') do |f|
            f.puts(JSON.generate(ts: Time.now.utc.iso8601, event: opts[:event], data: opts[:data]))
          end
        rescue StandardError
          nil
        end

        # Feature-flag lookup. When the operator left the key unset (nil):
        #   - honour explicit opts[:default] if provided
        #   - else for remote engines default critic/counterfactual/red_team_plan ON
        #     (S2/S3/S4 were coded but dark on grok/openai/anthropic hosts —
        #     that starved W1 diversity and produced resolve-monoculture DPO)
        #   - local ollama stays off unless the flag is explicitly true (cost)
        private_class_method def self.enabled?(opts = {})
          key = opts[:key]
          v = (PWN::Env.dig(:ai, :agent, key) if defined?(PWN::Env))
          return v unless v.nil?

          return opts[:default] if opts.key?(:default)

          eng = (PWN::Env.dig(:ai, :active) if defined?(PWN::Env)).to_s.downcase
          local = eng.empty? || eng == 'ollama'
          return false if local

          %i[critic counterfactual red_team_plan].include?(key.to_sym)
        rescue StandardError
          false
        end

        private_class_method def self.reflect_available?
          defined?(Reflect) && defined?(PWN::Env) && PWN::Env.is_a?(Hash) && PWN::Env.dig(:ai, :module_reflection)
        rescue StandardError
          false
        end

        private_class_method def self.in_curriculum?
          Thread.current[:pwn_curriculum] || (Thread.current[:pwn_swarm_depth] || 0).positive?
        end

        private_class_method def self.with_curriculum_guard
          Thread.current[:pwn_curriculum] = true
          yield
        ensure
          Thread.current[:pwn_curriculum] = false
        end

        # Author(s):: 0day Inc. <support@0dayinc.com>

        public_class_method def self.authors
          "AUTHOR(S):\n  0day Inc. <support@0dayinc.com>\n"
        end

        # Display Usage for this Module

        public_class_method def self.help
          puts "USAGE:
            # Run practice and return its result
            #{self}.practice(
              limit: 'optional - limit value consumed by #practice',
              prompts_per: 'optional - prompts per value consumed by #practice',
              dry_run: 'optional - dry run value consumed by #practice'
            )

            # Priority-fix 3 — Offline ORM/PRM pass over recent sessions so
            #{self}.offline_judge(
              local: 'optional - failure_only introspect does not starve the reward corpus.',
              since_hours: 'optional - lookback window (default 24)',
              limit: 'optional - max sessions to score (default 40)',
              prm: 'optional - also run Process Reward Model (default true)',
              commit: 'optional - write scores into learning/sentinel (default true)'
            )

            # P5 — W1 diversity report so monoculture is visible before DPO export
            #{self}.preference_balance(
              limit: 'optional - limit value consumed by #preference_balance (defaults to 10_000)',
              scrub: 'optional - scrub value consumed by #preference_balance'
            )

            # Run counterfactual and return its result
            #{self}.counterfactual(
              force: 'optional - force value consumed by #counterfactual',
              request: 'optional - request value consumed by #counterfactual',
              hint: 'optional - hint value consumed by #counterfactual',
              name: 'required - binary or identifier name',
              args: 'required - args value consumed by #counterfactual',
              error: 'optional - error value consumed by #counterfactual'
            )

            # S3 — Constitutional critic (with tool access)
            #{self}.critic(
              request: 'required - user request',
              final: 'required - candidate final answer',
              session_id: 'optional - for evidence lookup',
              text_only: 'optional - text only value consumed by #critic',
              force: 'optional - force value consumed by #critic'
            )

            # S4 — Adversarial plan review (grounded in telemetry)
            #{self}.red_team_plan(
              request: 'required - user goal',
              plan: 'required - numbered plan text from plan_first'
            )

            # C3 — Hindsight Experience Replay
            #{self}.hindsight(
              request: 'required - the FAILED goal',
              final: 'required - the final produced anyway',
              session_id: 'required - trajectory to relabel'
            )

            # W2 — Online LoRA A/B with regression gate
            #{self}.train_and_gate(
              base_model: 'optional - ollama base tag (default PWN::Env[:ai][:ollama][:model])',
              trainer: 'optional - :unsloth | :axolotl | :auto (default :auto)',
              dry_run: 'optional - export + build eval set but do not train (default true)'
            )

            # Run reclassify backlog and return its result
            #{self}.reclassify_backlog(
              limit: 'optional - limit value consumed by #reclassify_backlog'
            )

            # Run practice kpi and return its result
            #{self}.practice_kpi(
              results: 'optional - Array results value consumed by #practice_kpi',
              reclassified_n: 'optional - reclassified n value consumed by #practice_kpi'
            )

            # Week-over-week (or last-N snapshots) delta on repeating_n
            #{self}.repeating_trend(
              limit: 'optional - limit value consumed by #repeating_trend'
            )

            # Run calibrate and return its result
            #{self}.calibrate(
              predicted: 'optional - predicted value consumed by #calibrate',
              actual: 'optional - actual value consumed by #calibrate',
              engine: 'optional - engine value consumed by #calibrate'
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
