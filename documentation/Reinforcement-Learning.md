# Reinforcement Learning in pwn-ai

pwn-ai runs an in-context learning loop that can also export training data for
a local model. On hosts **with a trainer and GPU**, the path

`Curriculum.practice` → `Reward.export_dpo` → `Curriculum.train_and_gate`

can promote a new LoRA. Without a trainer the same path is **export-ready**
(datasets plus a manual CLI). Live improvement still happens in-context on
every turn.

![Reinforcement-learning loop](diagrams/reinforcement-learning.svg)

```
                       +------------------------------------------------+
        request -----> | Loop.run                                       |
                       |  plan_first -> Curriculum.red_team_plan  (S4)  |
                       |  Dispatch   -> Reward.semantic_ok        (R4)  |
                       |             -> Mistakes.record(cause:)         |
                       |  guard      -> Curriculum.counterfactual (S2)  |--> preference ledger (W1)
                       |  final      -> Curriculum.critic         (S3)  |
                       |             -> Reward.judge (outcome)    (R1)  |--> verify_as_reward (E3)
                       |             -> Reward.prm (process)      (R2)  |--> Sessions[step_reward] (C4)
                       |             -> Curriculum.hindsight      (C3)  |
                       |             -> Curriculum.calibrate      (W3)  |--> Metrics.calibration
                       |             -> Reward.sentinel           (R3)  |--> Mistakes(reward_signal)
                       +------------------------------------------------+
                                           |
                    Learning.consolidate (M1 semantic merge, M3 importance eviction)
                    MemoryIndex.recall_semantic (M2 similarity x recency x importance)
                    Registry.rank (C1 keyword fit + advantage + UCB)
                    Learning.exemplars_for (C2 prioritized replay, C4 minimal trace)
                                           |
              nightly cron --> Curriculum.practice (S1) --> Mistakes.resolve --> preference ledger (W1)
              weekly  cron --> Curriculum.train_and_gate (W2) --> optional LoRA --> A/B gate --> promote
                                           |
                    Extrospection.correlate (E2 world vs self join)
                    Metrics.changepoints (E1) --> Mistakes(cause: :env_drift)
```

## Reward signal (`PWN::AI::Agent::Reward`)

| ID | Method | What it does |
|----|--------|--------------|
| **R1** | `.judge` | Outcome score on `(request, final)` → `{score:0..1, verdict:, rationale:, key_step:}`. Replaces brittle success regexes. |
| **R2** | `.prm` | Process reward - per-tool-step `+1/0/-1` written into `Sessions[:step_reward]`. |
| **R3** | `.sentinel` | Compares proxy success rate vs judge mean vs user-correction rate. A large gap fingerprints `reward_signal` so the agent distrusts a lying proxy. |
| **R4** | `.semantic_ok` | Treats informational non-zero exits (e.g. `grep`/`rg` with no match) as benign. Metrics count them as OK; Mistakes only see true dispatch failures. |
| - | `.warm_sentinel` | Backfills the sentinel window from scored Learning outcomes so local hosts can engage proxy distrust without waiting for live remote introspect. |
| **W1** | `.record_preference` / `.export_dpo` | Preference ledger (`~/.pwn/preferences.jsonl`) from user corrections, resolve, counterfactual, critic, and practice. Caps per source; keeps trajectory-shaped pairs (winning traces / revised answers), not fix commentary. |
| - | `.scrub_preferences` / `.preference_balance` / `.generator_mix` | Ledger hygiene and source-mix health so one channel cannot flood preference export. |

## Credit assignment and replay

| ID | Where | What |
|----|-------|------|
| **C1** | `Registry.rank` + `Metrics.{ucb,thompson,advantage,prm_advantage}` | Live tool choice blends keyword fit, historical advantage, exploration bonus, and process-reward signal. |
| **C2** | `Learning.exemplars_for` | Prior successful traces ranked by judge score, recency, and keyword fit. Low-score "proxy success" rows are dropped when judge distrust is high. |
| **C3** | `Curriculum.hindsight` | On a failed goal, relabel what the trajectory *did* achieve (`success: 'soft'`). Soft rows stay out of hard SFT and are down-weighted in exemplars. |
| **C4** | `Learning.compress_exemplar` / skill build | Keep steps with positive `step_reward` so few-shot traces stay short. |

## Memory that stays high-signal

| ID | Where | What |
|----|-------|------|
| **M1** | `Learning.consolidate` | Semantic merge of near-duplicate lessons; importance-weighted eviction. |
| **M2** | `MemoryIndex.recall_semantic` | Rank MEMORY by similarity × recency × importance when embeddings are available. |
| **M3** | `Memory.remember` | Supports source, confidence, importance, and TTL so garbage self-evicts. |
| **M4** | `Learning.note_outcome` | Task outcomes go to `learning.jsonl` only. Memory `:lesson` is reserved for reflect, resolve, and human notes. `purge_noise` cleans older noisy lesson shapes. |

## Curriculum and self-play (`PWN::AI::Agent::Curriculum`)

| ID | Method | What |
|----|--------|------|
| **S1** | `.practice` | Mine top unresolved Mistakes → natural reproducers → self-play under the judge → auto-resolve on strong holdouts. Budget-exhaustion scars get "finish under N steps" prompts. |
| **S2** | `.counterfactual` | On repeated failure, fork an alt-persona branch, judge both, emit a preference pair. Skipped when the iteration budget is already under pressure. |
| **S3** | `.critic` | Constitutional critic of the final answer (can use tools). Under budget pressure, runs text-only so it cannot burn the remaining iterations. |
| **S4** | `.red_team_plan` | Adversarial review of the plan-first outline using Metrics / Mistakes / drift. |
| - | `.offline_judge` | Score recent sessions with outcome + process judges, warm the sentinel, optional ledger scrub. Meant for nightly cron on local hosts that only introspect failures live. |
| **C3** | `.hindsight` | HER relabel described above. |
| **W3** | `.calibrate` | Plan `p(success)=` vs actual outcome → per-engine Brier / overconfidence. Overconfidence can force plan_first + critic and tighten `max_iters`. |
| **W2** | `.train_and_gate` | Export SFT + DPO → optional LoRA train → promote only if the candidate wins on resolved margin, mean judge, smoke set, and a healthy preference diet. Without a trainer: `weight_loop: :export_ready`. |
| - | `.practice_kpi` | Week-over-week trend of repeating mistakes (outer curriculum health). |

## Budget pressure (iteration ceiling)

When unresolved `agent_loop` / `assistant_answer` budget-exhaustion fingerprints
dominate, the loop marks the budget path hot and tightens the live turn:

- lower effective `max_iters` (stricter on local/ollama engines than remote)
- **Last-iter force-final**: tools=nil on the final iteration so a text answer is required
- skip counterfactual / red-team forks that would spend more tool rounds
- still flush TaskSummarizer state and Learning on the exhaust path
- end-of-turn critic runs text-only under the same pressure

Practice prioritizes those scars with short-horizon "finish the task" prompts.
Raising `ai.agent.max_iters` or resolving the scar returns normal runway.

## Intro and extro join

| Where | What |
|-------|------|
| `Metrics.changepoints` + `Loop.attribute_cause` (**E1**) | Env-drift-attributed failures get `cause: :env_drift` and do not inflate `[REPEATING]`. |
| `Extrospection.correlate` (**E2**) | Lead-lag style joins ("tool X started failing after toolchain Y changed"). |
| `Reward.verify_as_reward` (**E3**) | Browser-backed claim checks can floor/cap the outcome score. |

## Config (`PWN::Env[:ai][:agent]`)

```yaml
:ai:
  :module_reflection: false  # gates Reflect lesson writing (not ORM alone)
  :agent:
    :critic: null            # S3 - nil = ON for remote engines, OFF for ollama
    :red_team_plan: null     # S4 - same auto policy
    :counterfactual: null    # S2 - same auto policy
    :hindsight: true         # C3 - hindsight relabel on failed turns (default true)
    :verify_as_reward: null  # E3 - nil = auto sample on claim-shaped answers
    :reward_llm: null        # nil = outcome/process judges use LLM teacher on remote
    :local_introspect: :failure_only   # ollama cost policy; remote always introspects
    :introspect_every_n: 3
    :max_iters: 25           # hard cap; budget pressure may lower effective value
```

## Cron self-improvement

```ruby
# Seeded idempotently by PWN::Cron.install_defaults (pwn setup --migrate):
PWN::Cron.install_defaults
# → curriculum_practice_nightly   0 3  * * *  Curriculum.practice(limit: 3)
# → curriculum_offline_judge     30 3  * * *  Curriculum.offline_judge(since_hours: 24, limit: 40)
# → curriculum_train_weekly       0 4  * * 0  Curriculum.train_and_gate(dry_run: true)  # false only with trainer+GPU
# → learning_consolidate_nightly  0 5  * * *  Learning.consolidate
```

`install_defaults` treats the legacy name `offline_judge_nightly` as an alias of
`curriculum_offline_judge` and will not double-seed the same slot.

## Tools exposed to the model

`reward_judge` · `reward_prm` · `reward_sentinel` · `reward_warm_sentinel` ·
`reward_preferences` · `reward_scrub_preferences` · `reward_preference_balance` ·
`reward_export_dpo` · `reward_generator_mix` · `curriculum_practice` ·
`curriculum_train` · `curriculum_hindsight` · `curriculum_offline_judge` ·
`curriculum_preference_balance` · `curriculum_practice_kpi` ·
`learning_purge_noise`

## Design claims

1. Process reward on real security tool traces, not only math demos (**R2**).
2. Automatic blame attribution: self vs environment drift (**E1** + **E2**).
3. Reward-hacking self-detection when proxy success diverges from the judge (**R3**).
4. Mistake-driven curriculum with regression-gated LoRA promotion when a trainer exists (**S1** + **W2**).
5. Preference pairs from normal agent work (corrections, resolve, critic, practice) with no separate human labelling queue (**W1**).
6. Export and promote only when the preference diet is diverse and trajectory-shaped.

## Preference signal quality

The in-context loop (semantic success, Mistakes, prompt injection) is the
default production path. The weight path is export-ready and gated. Controllers
keep it honest by:

1. Capping how much any one preference source can dominate the ledger.
2. Preferring winning tool traces and revised full answers over fix commentary.
3. Scrubbing historical prose-only pairs before DPO export.
4. Warming the sentinel from offline scores so local hosts are not stuck cold.
5. Requiring smoke checks and mean judge improvement before LoRA promote.
6. Treating budget exhaustion as a first-class practice target so the agent learns to finish.

## Design-priority STATUS

Living checklist for the reinforced feedback loop. Cite the Pri/ID here instead
of inventing new milestone labels for the same theme.

| Pri | ID | Control | Module(s) | Success criterion |
|-----|----|---------|-----------|-------------------|
| **P0** | W1 generator diversity | `Reward::TARGET_SOURCE_MIX` + `generator_mix` + mix-urgent force on critic/counterfactual | `reward.rb`, `curriculum.rb` | `generator_mix.healthy` OR `recommendation` not stuck on `suppress:mistakes_resolve`; trajectory_fraction ≥ 0.5 |
| **P0** | Introspect budget | `Learning::INTROSPECT_SOFT_MS` / `HARD_MS`; stage skip under soft/hard / budget-pressure mode | `learning.rb` | `auto_introspect` returns `stages_skipped` when over soft; post-answer path cannot re-thrash tool critic |
| **P0** | Local judge calibration | Heuristic score shrinkage + `confidence`; `Metrics.effective_rate` scales distrust by `judge_confidence` | `reward.rb`, `metrics.rb` | distrust×heuristic no longer fully replaces proxy; local no-trace highs capped |
| **P0** | Practice outer KPI | `Curriculum.practice_kpi` / `repeating_trend` → `~/.pwn/curriculum_kpi.jsonl` | `curriculum.rb` | week-over-week `delta_repeating` ≤ 0 on budget fingerprints after practice nights |
| **P0** | PRM sample efficiency | `PRM_MIN_N=5`, shrinkage to `PRM_FULL_N=20`, fleet coverage gate in `Registry.rank` | `metrics.rb`, `registry.rb` | `prm_advantage=0` until n≥5; rank delta=0 until ≥3 tools ready |
| **P0** | STATUS over flag archaeology | This table | docs | New work cites Pri/ID here, not fresh comments for the same theme |
| **ops** | Nightly diet close | `offline_judge` → `scrub_preferences` + `generator_mix` + `practice_kpi` | `curriculum.rb` | Cron path returns `scrub`/`generator_mix`/`practice_kpi`; raw resolve prose does not survive the night |
| **ops** | Shape backfill | `Reward.infer_shape` + scrub rewrite | `reward.rb` | Legacy shapeless rows get `winning_trace`/`revised_answer` when content warrants; traj_f measurable |
| **ops** | Mix in prompt | `Metrics.to_context` emits `W1 MIX:` when unhealthy | `metrics.rb` | Unhealthy diet visible every turn without a tool call |
| **P0** | Budget exhaust deepen | Last-iter force-final (tools=nil); skip CF under budget-pressure mode; hot caps 24 ollama / 75 remote; exhaust path `append_session`+`auto_introspect` | `loop.rb` | Exhaust returns a judged final, not a bare string; CF cannot re-enter under hot; last iter cannot tool-call |

### Config additions

```yaml
:ai:
  :agent:
    # Introspect budget (ms wall-clock inside auto_introspect)
    # INTROSPECT_SOFT_MS / HARD_MS are constants; override only via code/reload today.
    :critic: null            # also force-on when generator_mix.urgent includes critic
    :counterfactual: null    # also force-on when generator_mix.urgent includes counterfactual
```

### Tools (design-priority)

`reward_generator_mix` · `curriculum_practice_kpi` (plus existing reward/curriculum set)

---

**See also:** [pwn-ai Agent](pwn-ai-Agent.md) · [Mistakes](Mistakes.md) ·
[Skills, Memory & Learning](Skills-Memory-Learning.md) · [Cron](Cron.md)

[← Home](Home.md)
