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

        public_class_method def self.practice(opts = {})
          limit   = (opts[:limit] || 3).to_i
          per     = (opts[:prompts_per] || 2).to_i
          dry_run = opts[:dry_run] ? true : false
          return { skipped: 'recursion guard' } if in_curriculum?

          FileUtils.mkdir_p(CURRICULUM_DIR)
          targets = defined?(Mistakes) ? Mistakes.top(limit: limit, unresolved_only: true) : []
          results = []

          with_curriculum_guard do
            targets.each do |m|
              prompts = generate_reproducers(mistake: m, count: per)
              runs = dry_run ? [] : prompts.map { |p| self_play(prompt: p, tag: "practice:#{m[:signature]}") }
              solved = runs.select { |r| r[:score].to_f >= 0.7 }
              if !solved.empty? && defined?(Mistakes)
                fix = solved.max_by { |r| r[:score] }[:final].to_s.lines.first(3).join.strip[0, 400]
                Mistakes.resolve(signature: m[:signature], fix: "auto-curriculum: #{fix}")
                Reward.record_preference(prompt: prompts.first, rejected: m[:snippet].to_s, chosen: fix, source: :curriculum) if defined?(Reward)
              end
              results << { signature: m[:signature], tool: m[:tool], prompts: prompts, runs: runs.map { |r| { score: r[:score], verdict: r[:verdict] } }, resolved: !solved.empty? }
            end
          end
          log(event: :practice, data: results)
          { practiced: results.length, resolved: results.count { |r| r[:resolved] }, results: results, dry_run: dry_run }
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        # ----------------------------------------------------------------
        # S2 — Counterfactual A/B branching (real advantage estimation)
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # winner = PWN::AI::Agent::Curriculum.counterfactual(
        #   request: 'required - original user request',
        #   name: 'required - tool that keeps failing',
        #   args: 'required - args it was called with',
        #   error: 'required - the failure text',
        #   hint: 'optional - branch-A correction_hint (from Mistakes)'
        # )
        #
        # Returns { branch: :a|:b, content:, score: } — the winning branch's
        # suggestion, ready for Loop.run to inject as a synthetic tool result.
        # Loser/winner is written to Reward.preferences (W1).

        public_class_method def self.counterfactual(opts = {})
          return nil unless enabled?(key: :counterfactual)
          return nil if in_curriculum?

          request = opts[:request].to_s
          ensure_persona(name: ALT_NAME, role: 'You are an alternative-approach generator for pwn-ai. Given a failing tool call, propose ONE concrete DIFFERENT tool + args that would achieve the same sub-goal on this host. Reply with the tool call only, no prose.')

          branch_a = opts[:hint].to_s.strip
          branch_a = "retry #{opts[:name]} with corrected args" if branch_a.empty?
          branch_b = with_curriculum_guard do
            ask_persona(name: ALT_NAME, request: "Goal: #{request[0, 300]}\nFailing: #{opts[:name]}(#{opts[:args].to_s[0, 200]}) → #{opts[:error].to_s[0, 200]}\nPropose ONE different tool+args.")
          end
          return nil if branch_b.to_s.strip.empty?

          sa = score_branch(request: request, branch: branch_a)
          sb = score_branch(request: request, branch: branch_b)
          winner, loser, tag = sb > sa ? [branch_b, branch_a, :b] : [branch_a, branch_b, :a]
          Reward.record_preference(prompt: "#{request} | failing: #{opts[:name]} → #{opts[:error]}", rejected: loser, chosen: winner, source: :counterfactual) if defined?(Reward)
          { branch: tag, content: winner, score: [sa, sb].max, a: sa, b: sb }
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
          return { verdict: :pass, source: :disabled } unless enabled?(key: :critic)
          return { verdict: :pass, source: :recursion } if in_curriculum?

          ensure_persona(name: CRITIC_NAME, role: "You are pwn-ai's constitutional critic. Given a REQUEST and a candidate ANSWER, find ONE concrete, verifiable flaw (wrong fact, missing step, unsupported claim, broken command). You MAY call shell / extro_verify / pwn_eval to check. If none found reply exactly: PASS. Otherwise reply: FLAW: <one line>.")
          reply = with_curriculum_guard do
            ask_persona(name: CRITIC_NAME, request: "REQUEST:\n#{opts[:request].to_s[0, 800]}\n\nANSWER:\n#{opts[:final].to_s[0, 2_000]}")
          end
          if reply.to_s.strip.upcase.start_with?('PASS')
            { verdict: :pass, confidence: 0.7 }
          else
            flaw = reply.to_s.sub(/\AFLAW:\s*/i, '').strip[0, 300]
            Mistakes.record(tool: 'assistant_answer', error: "critic: #{flaw}", args: opts[:final].to_s[0, 200], session_id: opts[:session_id], source: :model) if defined?(Mistakes)
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

          ensure_persona(name: RED_TEAM_NAME, role: 'You are pwn-ai\'s adversarial plan reviewer. Given a numbered tool plan and telemetry from THIS host (tool success rates, known mistakes, environment drift), identify the ONE step most likely to fail and say why in ≤2 lines. Cite the metric/mistake/drift. If the plan is sound reply: SOUND.')
          telemetry = build_telemetry
          reply = with_curriculum_guard do
            ask_persona(name: RED_TEAM_NAME, request: "GOAL: #{opts[:request].to_s[0, 300]}\n\nPLAN:\n#{opts[:plan].to_s[0, 1_200]}\n\nHOST TELEMETRY:\n#{telemetry}")
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

          Learning.note_outcome(task: achieved, success: true, details: "HER-relabelled from failed: #{opts[:request].to_s[0, 100]}", session_id: opts[:session_id], tags: %w[hindsight her], score: 0.7) if defined?(Learning)
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
          dry_run = opts.key?(:dry_run) ? opts[:dry_run] : true
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
            result[:advice] = trainer.nil? ? "No trainer found. Install unsloth or axolotl, then re-run with dry_run:false. Datasets ready at #{sft&.[](:path)} + #{dpo&.[](:path)}." : 'dry_run — datasets + eval set exported; pass dry_run:false to train.'
            result[:manual_cli] = manual_train_cli(base: base, sft: sft, dpo: dpo, version: version)
            log(event: :train_and_gate, data: result)
            return result
          end

          adapter = run_trainer(trainer: trainer, base: base, sft: sft, dpo: dpo, version: version)
          return result.merge(error: 'trainer produced no adapter') unless adapter

          candidate = ollama_create(base: base, adapter: adapter, version: version)
          baseline  = state[:tag] || base
          gate = ab_gate(baseline: baseline, candidate: candidate, evalset: evalset)
          promoted = gate[:candidate_resolved] > gate[:baseline_resolved]
          if promoted
            state[:previous] = state[:tag]
            state[:tag] = candidate
            state[:current] = version
            state[:promoted_at] = Time.now.utc.iso8601
            state[:gate] = gate
            save_models(state: state)
          end
          result.merge(adapter: adapter, candidate: candidate, gate: gate, promoted: promoted)
        rescue StandardError => e
          { error: "#{e.class}: #{e.message}" }
        end

        # ----------------------------------------------------------------
        # W3 — Calibration head
        # ----------------------------------------------------------------

        # Supported Method Parameters::
        # PWN::AI::Agent::Curriculum.calibrate(predicted:, actual:, engine:)

        public_class_method def self.calibrate(opts = {})
          p = opts[:predicted].to_f.clamp(0.0, 1.0)
          a = opts[:actual].to_f.clamp(0.0, 1.0)
          brier = (p - a)**2
          Metrics.record_calibration(predicted: p, actual: a, brier: brier, engine: opts[:engine]) if defined?(Metrics) && Metrics.respond_to?(:record_calibration)
          { predicted: p, actual: a, brier: brier.round(4) }
        end

        # ----------------------------------------------------------------
        # privates
        # ----------------------------------------------------------------

        private_class_method def self.generate_reproducers(opts = {})
          m = opts[:mistake]
          count = opts[:count] || 2
          if reflect_available?
            req = "Generate #{count} MINIMAL pwn-ai user prompts (one per line, ≤15 words each) that would naturally trigger this failure signature so the agent can practise avoiding it:\n  tool: #{m[:tool]}\n  error: #{m[:error]}\n  sample: #{m[:snippet].to_s[0, 200]}\nOutput ONLY the prompts, one per line."
            resp = Reflect.on(request: req, suppress_pii_warning: true).to_s
            lines = resp.lines.map { |l| l.gsub(/^\s*[-*\d.)]+\s*/, '').strip }.reject(&:empty?).first(count)
            return lines unless lines.empty?
          end
          ["reproduce mistake #{m[:signature]}: #{m[:tool]} → #{m[:error].to_s[0, 100]}"]
        end

        private_class_method def self.self_play(opts = {})
          sid = PWN::Sessions.create(title: "curriculum #{opts[:tag]}")[:id]
          final = Loop.run(request: opts[:prompt], session_id: sid, enabled_toolsets: %w[terminal pwn memory learning])
          v = Reward.judge(request: opts[:prompt], final: final, session_id: sid, commit: false)
          { session_id: sid, prompt: opts[:prompt], final: final, score: v[:score], verdict: v[:verdict] }
        rescue StandardError => e
          { prompt: opts[:prompt], error: e.message, score: 0.0 }
        end

        private_class_method def self.score_branch(opts = {})
          return 0.5 unless reflect_available?

          req = "Goal: #{opts[:request]}\nProposed next action: #{opts[:branch]}\nOn a scale 0.0-1.0, how likely is this to advance the goal on a Kali Linux host? Reply with ONLY the number."
          Reflect.on(request: req, suppress_pii_warning: true).to_s[/[01](?:\.\d+)?/].to_f.clamp(0.0, 1.0)
        rescue StandardError
          0.5
        end

        private_class_method def self.ask_persona(opts = {})
          return nil unless defined?(Swarm)

          r = Swarm.ask(name: opts[:name], request: opts[:request])
          r.is_a?(Hash) ? r[:reply].to_s : r.to_s
        rescue StandardError
          nil
        end

        private_class_method def self.ensure_persona(opts = {})
          return unless defined?(Swarm)
          return if Swarm.personas.key?(opts[:name].to_sym)

          Swarm.spawn(name: opts[:name], role: opts[:role], toolsets: %w[terminal pwn extrospection], max_iters: 8)
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
          rows = defined?(Mistakes) ? Mistakes.top(limit: 20, unresolved_only: false) : []
          rows.map { |m| { signature: m[:signature], prompt: generate_reproducers(mistake: m, count: 1).first } }
        end

        private_class_method def self.ab_gate(opts = {})
          evalset  = opts[:evalset]
          baseline = replay_on(tag: opts[:baseline], evalset: evalset)
          candid   = replay_on(tag: opts[:candidate], evalset: evalset)
          { baseline: opts[:baseline], candidate: opts[:candidate], baseline_resolved: baseline, candidate_resolved: candid, evalset_size: evalset.length }
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

        private_class_method def self.detect_trainer(opts = {})
          pref = opts[:preference].to_s
          return pref.to_sym if %w[unsloth axolotl].include?(pref) && trainer_installed?(name: pref)

          %w[unsloth axolotl].find { |t| trainer_installed?(name: t) }&.to_sym
        end

        private_class_method def self.trainer_installed?(opts = {})
          !`python3 -c "import #{opts[:name]}" 2>/dev/null; echo $?`.strip.end_with?('1')
        rescue StandardError
          false
        end

        private_class_method def self.run_trainer(opts = {})
          out_dir = File.join(DPO_DIR_CONST, "pwn-v#{opts[:version]}")
          FileUtils.mkdir_p(out_dir)
          script = File.join(out_dir, 'train.py')
          File.write(script, unsloth_script(base: opts[:base], sft: opts[:sft][:path], dpo: opts[:dpo][:path], out: out_dir))
          _o, e, s = Open3.capture3("python3 #{script} 2>&1")
          warn "[pwn-ai/curriculum] trainer: #{e[0, 400]}" unless s.success?
          adapter = File.join(out_dir, 'adapter')
          Dir.exist?(adapter) ? adapter : nil
        rescue StandardError
          nil
        end

        private_class_method def self.ollama_create(opts = {})
          tag = "pwn-v#{opts[:version]}"
          modelfile = File.join(File.dirname(opts[:adapter]), 'Modelfile')
          File.write(modelfile, "FROM #{opts[:base]}\nADAPTER #{opts[:adapter]}\n")
          system("ollama create #{tag} -f #{modelfile} >/dev/null 2>&1")
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

        private_class_method def self.enabled?(opts = {})
          v = (PWN::Env.dig(:ai, :agent, opts[:key]) if defined?(PWN::Env))
          v.nil? ? (opts[:default] || false) : v
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
          puts <<~USAGE
            USAGE:
              # Tier 4 — self-play
              PWN::AI::Agent::Curriculum.practice(limit: 3)                     # S1 mistake-driven auto-curriculum
              PWN::AI::Agent::Curriculum.counterfactual(request:, name:, args:, error:, hint:)  # S2 A/B → DPO pair
              PWN::AI::Agent::Curriculum.critic(request:, final:)               # S3 tool-armed constitutional critic
              PWN::AI::Agent::Curriculum.red_team_plan(request:, plan:)         # S4 telemetry-grounded plan review
              PWN::AI::Agent::Curriculum.hindsight(request:, final:, session_id:) # C3 HER relabel

              # Tier 5 — close the weight loop
              PWN::AI::Agent::Curriculum.train_and_gate(dry_run: true)          # W2 SFT+DPO→LoRA→A/B gate→promote
              PWN::AI::Agent::Curriculum.calibrate(predicted: 0.8, actual: 1.0) # W3 Brier → Metrics[:calibration]

              Cron self-improvement (nightly):
                PWN::Cron.create(name: 'self_play', schedule: '0 3 * * *',
                  ruby: 'PWN::AI::Agent::Curriculum.practice(limit: 5)')
                PWN::Cron.create(name: 'weight_loop', schedule: '0 4 * * 0',
                  ruby: 'PWN::AI::Agent::Curriculum.train_and_gate(dry_run: false)')

              Config (PWN::Env[:ai][:agent]):
                :critic         - Boolean, run S3 before every note_outcome
                :red_team_plan  - Boolean, run S4 after every plan_first
                :counterfactual - Boolean, run S2 on REPEAT_THRESHOLD
                :hindsight      - Boolean, HER-relabel failures (default true)

              #{self}.authors
          USAGE
        end
      end
    end
  end
end
