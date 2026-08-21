---
name: pwn-ai-agent-reward
description: Drive PWN::AI::Agent::Reward from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Reward
  source: pwn/ai/agent/reward.rb
---

# PWN::AI::Agent::Reward

PWN::AI::Agent::Reward is the OUTCOME reward model for the pwn-ai reinforcement-learning loop. It replaces the regex-proxy reward that previously drove Learning.infer_success / Loop.record_metrics with four calibrated signals: R1 .judge — LLM Outcome Reward Model (ORM). Scores the FINAL answer against the user request → {score:0..1, verdict: :solved|:partial|:wrong|:refused, rationale:}. Scalar, not boolean. R2 .prm — Process Reward Model. Per-tool-call "did this step advance toward the goal?" → step_reward tagged onto every Sessions entry so credit is assignable INSIDE a trajectory, not just at its boundary. First PRM applied to security tooling. R3 .sentinel — Reward-hacking detector. Tracks proxy vs judge vs (1 - user_correction_rate); when they diverge by > SENTINEL_GAP the reward signal itself is fingerprinted as a Mistake so the operator sees "your success_rate is a lie" in KNOWN MISTAKES. R4 .semantic_ok — Structured tool-result classifier. Knows that `grep exit 1` == "no match", not "failure"; kills the phantom-mistake class (31f1871b8a15) that made the loop's #1 negative signal a false positive it created itself. Reward also owns the PREFERENCE-PAIR ledger (~/.pwn/preferences.jsonl) that turns pwn's naturally-generated (rejected, chosen) pairs — from user corrections, mistakes_resolve, and Curriculum.counterfactual A/B branches — into a DPO export (W1). This is the ONLY path from in-context learning to weight-level policy improvement. E3 .verify_as_reward — grounds any final containing a checkable claim (CVE / version / cited URL) via Extrospection.verify and maps the browser verdict onto the reward scalar. Hallucination becomes a measurable −reward, not just a warning. .judge prefers a cheap LLM ORM (direct engine .chat, short timeout, no Reflect / module_reflection gate). Reflect.on is used only when the operator enabled module_reflection (teacher engine). Heuristic token-overlap is LAST RESORT so proxy_distrust haircuts blend toward a real outcome signal, not bag-of-words overlap.

## When to use

Call `PWN::AI::Agent::Reward` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/reward.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Reward.help
PWN::AI::Agent::Reward.judge(opts)
```

## Public methods

- `judge`
- `prm`
- `plan_coverage`
- `sentinel`
- `proxy_distrust`
- `set_proxy_distrust`
- `clear_proxy_distrust`
- `reset_sentinel`
- `warm_sentinel`
- `semantic_ok`
- `recoverable_shape`
- `verify_as_reward`
- `record_preference`
- `write_source_quota`
- `generator_mix`
- `infer_shape`
- `usable_preference`
- `scrub_preferences`
- `preference_balance`
- `preferences`
- `export_dpo`
- `reset`
- `judge_sample_weight`
- `authors`
- `help`

## Source

`pwn/ai/agent/reward.rb`

## Verification

`PWN::AI::Agent::Reward.respond_to?(:judge)` after the
module is loaded. Read the source for parameter names.
