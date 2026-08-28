---
name: pwn-ai-agent-policy
description: Drive PWN::AI::Agent::Policy from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Policy
  source: pwn/ai/agent/policy.rb
---

# PWN::AI::Agent::Policy

PWN::AI::Agent::Policy is the LIVE tabular RL controller that pwn-ai did not have before R5. Everything else in the harness is retrieval-plus-policy: scores are written to disk and re-injected as prose, or exported later for optional LoRA. This module is the missing MDP: state s — discretized (kind, task, plan, completeness, usable, last, fail) action a — tool name, or "final" reward r — step: 0 (spam cost −0.01 after 8 tools); terminal: judge × confidence next s' — state after the tool result Each Loop turn is one episode. Transitions land in ~/.pwn/policy_traj.jsonl. Q(s,a) and REINFORCE logits H(s,a) are updated from those tuples and persisted in ~/.pwn/policy.json. The learned Q values are an ADVISORY term in Registry.rank. They never replace TaskSummarizer planning, plan_first, or CORE_TOOLS. Disable with PWN::Env[:ai][:agent][:policy] = false.

## When to use

Call `PWN::AI::Agent::Policy` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/policy.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Policy.help
PWN::AI::Agent::Policy.state(opts)
```

## Public methods

- `state`
- `cold`
- `warm`
- `episode_budget_met`
- `begin_episode`
- `observe_step`
- `finish`
- `update_q`
- `update_pg`
- `q`
- `value`
- `advantage`
- `recommend`
- `current_state`
- `current_episode`
- `detach_episode`
- `attach_episode`
- `load`
- `save`
- `trajectories`
- `stats`
- `evaluate`
- `to_context`
- `lean`
- `reset`
- `enabled`
- `authors`
- `help`
- `warmup`
- `maybe_warmup`
- `attach_episode!`
- `cold?`
- `detach_episode!`
- `enabled?`
- `episode_budget_met?`
- `lean!`
- `maybe_warmup!`
- `update_pg!`
- `update_q!`
- `warm?`
- `warmup!`

## Source

`pwn/ai/agent/policy.rb`

## Verification

`PWN::AI::Agent::Policy.respond_to?(:state)` after the
module is loaded. Read the source for parameter names.
