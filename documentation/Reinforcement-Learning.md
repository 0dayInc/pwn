# Reinforcement Learning in pwn-ai

pwn-ai learns while you work. Most of that learning stays **in context**: the
agent writes what happened to disk and puts the useful bits back into the next
prompt. On a host **with a trainer and a GPU**, the same data can also train a
local adapter.

`Curriculum.practice` -> `Reward.export_dpo` -> `Curriculum.train_and_gate`

That path can promote a new local adapter when the candidate beats the current
one. Without a trainer it still **exports** the datasets and a manual CLI. Live
improvement does not wait on weights.

![Reinforcement-learning loop](diagrams/reinforcement-learning.svg)

```
                       +------------------------------------------------+
        request -----> | Loop.run                                       |
                       |  plan_first -> Curriculum.red_team_plan        |
                       |  Dispatch   -> Reward.semantic_ok              |
                       |             -> Mistakes.record(cause:)         |
                       |  guard      -> Curriculum.counterfactual       |--> preference ledger
                       |  final      -> Curriculum.critic               |
                       |             -> Reward.judge (outcome)          |--> verify_as_reward
                       |             -> Reward.prm (process)            |--> Sessions[step_reward]
                       |             -> Curriculum.hindsight            |
                       |             -> Curriculum.calibrate            |--> Metrics.calibration
                       |             -> Reward.sentinel                 |--> Mistakes(reward_signal)
                       +------------------------------------------------+
                                           |
                    Learning.consolidate (merge + importance-evict)
                    MemoryIndex.recall_semantic (similarity x recency x importance)
                    Registry.rank (keyword + UCB + Q-advantage + tool_preference)
                    Policy (live Q / REINFORCE on a judge-scored MDP)
                    Learning.exemplars_for (prioritized replay, short traces)
                                           |
              nightly cron --> Curriculum.practice --> Mistakes.resolve --> preference
              weekly  cron --> Curriculum.train_and_gate --> optional adapter --> A/B gate --> promote
                                           |
                    Extrospection.correlate (world vs self)
                    Metrics.changepoints (CUSUM) --> Mistakes(cause: :env_drift)
```

## Live Policy on every turn (`PWN::AI::Agent::Policy`)

This is the live numeric controller. It does not replace planning.

| Piece | What it is |
|---|---|
| State | request kind, task family, plan quality, answer completeness, usable-result, last action, fail bin, and engine |
| Action | tool name, or `final` |
| Step reward | `Reward.semantic_ok` hygiene (`+0.05` / `-0.20`) |
| Terminal reward | `Reward.judge` score (skipped when the cheap proxy is untrusted and there is no judge) |
| Updates | Q-learning (`alpha=0.15`, `gamma=0.85`) and REINFORCE (`alpha=0.05`). Stored trajectories replay twice on warmup so a short table is not empty advice. |
| Budget | Eight finished episodes (live or warmup-credited) unlock greedy suggestions. Until then the prompt omits them. |
| Steer | Q-advantage in `Registry.rank` once the episode budget is met; keyword fit and CORE_TOOLS still come first. Suggested actions follow `Registry.preference_order` (`ai.agent.tool_preference`). |
| Files | `~/.pwn/policy.json`, `~/.pwn/policy_traj.jsonl` |
| Tools | `policy_stats` · `policy_evaluate` · `policy_recommend` (inspect only) |
| Off switch | `ai.agent.policy: false` |

Loop calls `begin_episode` before the first rank, `observe_step` after each
tool, and `finish` from `Learning.auto_introspect` (or Loop if introspect is
skipped). `Learning.gc_stores` can trim old trajectories without dropping
high-return / high-score episodes.

## Reward signal (`PWN::AI::Agent::Reward`)

| Method | What it does |
|--------|--------------|
| **R1** `.judge` | Cheap LLM outcome score on `(request, final)` -> `{score:0..1, verdict:, rationale:, key_step:, source:}`. Calls the active engine `.chat` with a short timeout (default 12s). `Reflect.on` is used only when `module_reflection` is on. Fallback scores completeness, plan cover, claims, and tool-trace echo. Token overlap is only a small on-topic gate. |
| **R2** `.prm` | Process reward - per-tool-step `+1/0/-1` written into `Sessions[:step_reward]`. |
| **R3** `.sentinel` | Compares proxy success rate vs judge mean vs user-correction rate. A large gap fingerprints `reward_signal` so the agent distrusts a lying proxy. |
| **R4** `.semantic_ok` | Treats informational non-zero exits (for example `grep` / `rg` with no match) as benign. Metrics count them as OK; Mistakes only see true dispatch failures. |
| **R5** `Policy` (live MDP) | Tabular Q-learning + REINFORCE on real Loop turns. Q-advantage is an advisory `Registry.rank` term and never replaces TaskSummarizer or plan_first. |
| `.warm_sentinel` | Backfills the sentinel window from scored Learning outcomes so local hosts can engage proxy distrust without waiting for live remote introspect. |
| `.record_preference` / `.export_dpo` | Preference ledger (`~/.pwn/preferences.jsonl`) from user corrections, resolve, counterfactual, critic, and practice. Caps per source; keeps trajectory-shaped pairs (winning traces / revised answers), not fix commentary. |
| `.scrub_preferences` / `.preference_balance` / `.generator_mix` | Ledger hygiene and source-mix health so one channel cannot flood preference export. |

## Credit assignment and replay

| Where | What |
|-------|------|
| **C1** `Registry.rank` + `Metrics.{ucb,thompson,advantage,prm_advantage}` + `Policy.advantage` | Live tool choice blends keyword fit, historical advantage, exploration bonus, process-reward signal, and (once the episode budget is met) Q(s,a)-V(s). Neighbor states fill cold (s,a) pairs. |
| **C2** `Learning.exemplars_for` | Prior successful traces ranked by judge score, recency, and keyword fit. Low-score "proxy success" rows are dropped when judge distrust is high. |
| **C3** `Curriculum.hindsight` | On a failed goal, relabel what the trajectory *did* achieve (`success: 'soft'`). Soft rows stay out of hard supervised export and are down-weighted in exemplars. |
| **C4** `Learning.compress_exemplar` / skill build | Keep steps with positive `step_reward` so few-shot traces stay short. |

## Memory that stays high-signal

| Where | What |
|-------|------|
| **M1** `Learning.consolidate` | Semantic merge of near-duplicate lessons; importance-weighted eviction. |
| **M2** `MemoryIndex.recall_semantic` | Rank MEMORY by similarity x recency x importance when embeddings are available. |
| **M3** `Memory.remember` | Supports source, confidence, importance, and TTL so garbage self-evicts. |
| **M4** `Learning.note_outcome` | Task outcomes go to `learning.jsonl` only. Memory `:lesson` is reserved for reflect, resolve, and human notes. `purge_noise` cleans older noisy lesson shapes. |

## Curriculum and self-play (`PWN::AI::Agent::Curriculum`)

| Method | What |
|--------|------|
| **S1** `.practice` | Mine top unresolved Mistakes -> natural reproducers -> self-play under the judge -> auto-resolve on strong holdouts. Budget-exhaustion scars get "finish under N steps" prompts. |
| **S2** `.counterfactual` | On repeated failure, fork an alt-persona branch, judge both, emit a preference pair. Skipped when the iteration budget is already under pressure. |
| **S3** `.critic` | Constitutional critic of the final answer (can use tools). Under budget pressure, runs text-only so it cannot burn the remaining iterations. |
| **S4** `.red_team_plan` | Adversarial review of the plan-first outline using Metrics / Mistakes / drift. |
| `.offline_judge` | Score recent sessions with outcome + process judges, warm the sentinel, optional ledger scrub. Meant for nightly cron on local hosts that only introspect failures live. |
| `.hindsight` | Relabel described above. |
| **W3** `.calibrate` | Plan `p(success)=` vs actual outcome -> per-engine Brier / overconfidence. Overconfidence can force plan_first + critic. It does **not** shrink this request's `max_iters`. |
| **W2** `.train_and_gate` | Export supervised + preference data -> optional local adapter train -> promote only if the candidate wins on resolved margin, mean judge, smoke set, and a healthy preference diet. Without a trainer: `weight_loop: :export_ready`. |
| **W1** `.record_preference` | Preference ledger from corrections, resolve, counterfactual, critic, and practice. |
| `.practice_kpi` | Week-over-week trend of repeating mistakes (outer curriculum health). |

## Budget pressure (iteration ceiling)

When unresolved `agent_loop` / `assistant_answer` budget-exhaustion fingerprints
dominate, the loop marks the budget path hot and tightens *side work* only:

- skip counterfactual / red-team forks that would spend more tool rounds
- **do not abort** with `[pwn-ai] iteration budget exhausted`
- **do not shrink `max_iters`** - yesterday's scars must not abort this request

Practice prioritizes those scars with short-horizon "finish the task" prompts.
`Loop.run` has no hard ceiling — CORE_TOOLS stay until `may_finalize?`.

## Design-priority STATUS

This is the live control list. Track the outcomes, not source comments.

`PRM_MIN_N` / `PRM_FULL_N` gate process-reward rank until enough samples exist.

| Priority | Control | Success look |
|----------|---------|--------------|
| must | Preference-source diversity (`Reward::TARGET_SOURCE_MIX` + `generator_mix`) | Mix is healthy, or the recommendation is not stuck suppressing `mistakes_resolve`; trajectory-shaped pairs stay at least half the ledger |
| must | Introspect budget (`Learning::INTROSPECT_SOFT_MS` / `HARD_MS`) | `auto_introspect` skips extra stages when over the soft cap so the post-answer path cannot re-thrash a tool critic |
| high | Local judge calibration | Heuristic scores shrink by confidence; a local no-trace high does not fully replace the proxy |
| ops | Cheap LLM outcome judge | Remote turns grade with the engine chat even when `module_reflection` is off; token overlap is last-resort |
| ops | Outcome-signal haircut (`judge_sample_weight`) | Proxy distrust blends toward engine scores, not bag-of-words overlap |
| high | Practice outer KPI (`Curriculum.practice_kpi`) | Week-over-week repeating-mistake trend on budget fingerprints is not rising after practice nights |
| next | Process-reward sample efficiency | `prm_advantage` stays 0 until enough samples exist; rank does not swing on a tiny fleet |
| ops | Nightly diet close | `offline_judge` then scrub + mix + KPI so raw resolve prose does not survive the night |
| ops | Shape backfill (`Reward.infer_shape`) | Legacy shapeless rows become `winning_trace` / `revised_answer` when the content warrants |
| ops | Mix in prompt | `Metrics.to_context` emits `MIX:` when preference sources are unhealthy |
| must | Budget exhaust | Loop.run does **not** abort on a round cap or emit `[pwn-ai] iteration budget exhausted`. Keep CORE_TOOLS until `may_finalize?`. Skip extra CF forks when old budget scars are hot; **do not shrink max_iters** |

## Intro and extro join

| Where | What |
|-------|------|
| **E1** `Metrics.changepoints` + `Loop.attribute_cause` | Env-drift-attributed failures get `cause: :env_drift` and do not inflate `[REPEATING]`. |
| **E2** `Extrospection.correlate` | Lead-lag style joins ("tool X started failing after toolchain Y changed"). |
| **E3** `Reward.verify_as_reward` | Browser-backed claim checks can floor/cap the outcome score. |

## Config (`PWN::Env[:ai][:agent]`)

```yaml
:ai:
  :module_reflection: false  # gates Reflect lesson writing (not the judge alone)
  :agent:
    :critic: null            # nil = ON for remote engines, OFF for ollama
    :red_team_plan: null     # same auto rule
    :counterfactual: null    # same auto rule
    :hindsight: true         # hindsight relabel on failed turns (default true)
    :policy: true            # live tabular Q / REINFORCE (advisory rank only)
    :verify_as_reward: null  # nil = auto sample on claim-shaped answers
    :reward_llm: null        # nil = outcome/process judges use LLM teacher on remote
    :reward_model: null      # optional cheaper model id for ORM/PRM (nil = engine default)
    :reward_llm_timeout: 12  # cheap ORM chat timeout seconds (clamped 2..30)
    :local_introspect: :failure_only   # ollama cost rule; remote always introspects
    :introspect_every_n: 3
    :max_iters: 777          # hard cap for this request; scars do not lower it
    :defer_introspect: true  # post-answer Learning after the user-visible reply
    :prompt_cache: true      # engine-native prefix cache (not ollama / openwebui)
    :tool_preference: [memory_recall, session_recall, skills_recall, pwn_eval, shell, mistakes_record, mistakes_resolve, learning_note_outcome, memory_remember, skills_update]
```

## Cron self-improvement

```ruby
# Seeded idempotently by PWN::Cron.install_defaults (pwn setup --migrate):
PWN::Cron.install_defaults
# -> curriculum_practice_nightly   0 3  * * *  Curriculum.practice(limit: 3)
# -> curriculum_offline_judge     30 3  * * *  Curriculum.offline_judge(since_hours: 24, limit: 40)
# -> curriculum_train_weekly       0 4  * * 0  Curriculum.train_and_gate(dry_run: true)  # false only with trainer+GPU
# -> learning_consolidate_nightly  0 5  * * *  Learning.consolidate
```

`install_defaults` treats the legacy name `offline_judge_nightly` as an alias of
`curriculum_offline_judge` and will not double-seed the same slot.
`pwn setup` also starts the background cron worker so these YAML jobs fire
without a per-job crontab line.

## Tools exposed to the model

`reward_judge` · `reward_prm` · `reward_sentinel` · `reward_warm_sentinel` ·
`reward_preferences` · `reward_scrub_preferences` · `reward_preference_balance` ·
`reward_export_dpo` · `reward_generator_mix` · `curriculum_practice` ·
`curriculum_train` · `curriculum_hindsight` · `curriculum_offline_judge` ·
`curriculum_preference_balance` · `curriculum_practice_kpi` · `policy_stats` ·
`policy_evaluate` · `policy_recommend` · `learning_purge_noise`

## What this stack actually does

1. Process reward on real security tool traces, not only math demos.
2. Automatic blame: self vs environment drift.
3. Reward-hacking self-detection when proxy success diverges from the judge.
4. Mistake-driven curriculum with regression-gated adapter promotion when a trainer exists.
5. Preference pairs from normal agent work (corrections, resolve, critic, practice) with no separate human labelling queue.
6. Export and promote only when the preference diet is diverse and trajectory-shaped.
7. Live tabular Q-learning + REINFORCE on real Loop turns, used only as advice next to planning.

## Preference signal quality

The in-context loop (semantic success, Mistakes, prompt injection) is the
default production path. The weight path is export-ready and gated. Controllers
keep it honest by:

1. Capping how much any one preference source can dominate the ledger.
2. Preferring winning tool traces and revised full answers over fix commentary.
3. Scrubbing historical prose-only pairs before preference export.
4. Warming the sentinel from offline scores so local hosts are not stuck cold.
5. Requiring smoke checks and mean judge improvement before adapter promote.
6. Treating budget exhaustion as a first-class practice target so the agent learns to finish.

---

**See also:** [pwn-ai Agent](pwn-ai-Agent.md) · [Mistakes](Mistakes.md) ·
[Skills, Memory & Learning](Skills-Memory-Learning.md) · [Cron](Cron.md)

[← Home](Home.md)
