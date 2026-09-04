---
name: pwn-ai-agent-learning
description: Drive PWN::AI::Agent::Learning from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Learning
  source: pwn/ai/agent/learning.rb
---

# PWN::AI::Agent::Learning

PWN::AI::Agent::Learning is the self-improvement engine that closes the pwn-ai feedback loop. It captures task outcomes, mines session transcripts for durable lessons, promotes successful workflows into reusable skills, and keeps ~/.pwn lean (memory + learning.jsonl + mistakes + sessions) so the agent gets sharper over time instead of accumulating noise. Data flows: Loop.run --(tool telemetry)--> Metrics.record Loop.run --(final answer)----> Learning.auto_introspect (opt-in) auto_introspect --(throttled)--> Learning.gc_stores! # ~/.pwn lean model --(tool calls)------> learning_note_outcome / _distill_skill PromptBuilder <----------------- Learning.to_context + Metrics.to_context Everything is file-backed under ~/.pwn so it survives across REPL restarts and is shared by every future session.

## When to use

Call `PWN::AI::Agent::Learning` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/learning.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Learning.help
PWN::AI::Agent::Learning.note_outcome(opts)
```

## Public methods

- `note_outcome`
- `consistency_check`
- `disputed_save`
- `outcomes`
- `stats`
- `to_context`
- `exemplars_for`
- `export_finetune`
- `distill_skill`
- `update_skill`
- `reflect`
- `auto_introspect`
- `flip_last_outcome`
- `consolidate`
- `reset`
- `reconcile_verdict_tags`
- `prune_outcomes`
- `lean`
- `gc_stores`
- `purge_noise`
- `lesson_record`
- `lesson_observe`
- `lesson_prompt`
- `list_conflicted`
- `requeue_conflicted`
- `compact`
- `authors`
- `help`
- `compact!`
- `gc_stores!`
- `lean!`
- `prune_outcomes!`
- `reconcile_verdict_tags!`

## Source

`pwn/ai/agent/learning.rb`

## Verification

`PWN::AI::Agent::Learning.respond_to?(:note_outcome)` after the
module is loaded. Read the source for parameter names.
