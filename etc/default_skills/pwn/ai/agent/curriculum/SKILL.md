---
name: pwn-ai-agent-curriculum
description: Drive PWN::AI::Agent::Curriculum from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Curriculum
  source: pwn/ai/agent/curriculum.rb
---

# PWN::AI::Agent::Curriculum

PWN::AI::Agent::Curriculum is Tier 4/5 of the pwn-ai reinforcement loop — the SELF-PLAY layer that turns the agent from a passive experience-recorder into an active learner: S1 .practice — Mistake-driven auto-curriculum. Reads Mistakes.top(unresolved), asks Reflect to generate 3 minimal reproducer prompts per signature, self-plays each under Loop.run, and auto-mistakes_resolve when Reward.judge says the practice run solved it. THE AGENT PRACTISES ITS OWN WEAKNESSES OVERNIGHT. S2 .counterfactual — On a repeated in-turn failure, forks: branch A continues with the correction_hint, branch B asks an alt persona for a different tool. Reward.judge picks the winner; (loser, winner) → Reward.record_preference. Real advantage estimation, not imagined rollouts. S3 .critic — Constitutional critic persona with TOOL ACCESS (can shell/extro_verify the claim). Runs BEFORE note_outcome; its verdict feeds Reward.judge and its concrete flaw becomes a preference pair when the agent self-corrects. S4 .red_team_plan — After plan_first, an adversarial persona reviews the plan against THIS host's Metrics/Mistakes/extro_drift and injects a pre-emptive correction_hint on the step it predicts will fail. C3 .hindsight — Hindsight Experience Replay. On failure, asks the judge "what DID this trajectory accomplish?", relabels the episode with the achieved-goal as success:true. Free positive samples from failures — first HER on real tool traces. W2 .train_and_gate — export_finetune + export_dpo → local LoRA (unsloth/axolotl if installed) → replay Mistakes.top on vN vs vN+1 → promote iff resolved(N+1) > resolved(N). Fully autonomous weight-level self-improvement with a regression gate. W3 .calibrate — Tracks plan_first predicted p(success) vs actual outcome → Brier score in Metrics. All entry points are cron-safe (never raise into the caller) and depth-guarded via Swarm's Thread.current[:pwn_swarm_depth] so a curriculum run cannot recurse into itself.

## When to use

Call `PWN::AI::Agent::Curriculum` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/curriculum.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Curriculum.help
PWN::AI::Agent::Curriculum.practice(opts)
```

## Public methods

- `practice`
- `offline_judge`
- `preference_balance`
- `counterfactual`
- `critic`
- `red_team_plan`
- `hindsight`
- `train_and_gate`
- `practice_kpi`
- `repeating_trend`
- `calibrate`
- `authors`
- `help`

## Source

`pwn/ai/agent/curriculum.rb`

## Verification

`PWN::AI::Agent::Curriculum.respond_to?(:practice)` after the
module is loaded. Read the source for parameter names.
