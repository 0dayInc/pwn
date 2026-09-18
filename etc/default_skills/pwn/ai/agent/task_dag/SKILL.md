---
name: pwn-ai-agent-taskdag
description: Drive PWN::AI::Agent::TaskDAG from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::TaskDAG
  source: pwn/ai/agent/task_dag.rb
---

# PWN::AI::Agent::TaskDAG

Planner/executor split: YAML task DAGs with per-step checkpoints.

## When to use

Call `PWN::AI::Agent::TaskDAG` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/task_dag.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::TaskDAG.help
PWN::AI::Agent::TaskDAG.required_bins(opts)
```

## Public methods

- `required_bins`
- `plan`
- `execute`
- `resume`
- `authors`
- `help`

## Source

`pwn/ai/agent/task_dag.rb`

## Verification

`PWN::AI::Agent::TaskDAG.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
