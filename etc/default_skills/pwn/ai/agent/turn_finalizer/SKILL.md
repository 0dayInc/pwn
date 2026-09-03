---
name: pwn-ai-agent-turnfinalizer
description: Drive PWN::AI::Agent::TurnFinalizer from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::TurnFinalizer
  source: pwn/ai/agent/turn_finalizer.rb
---

# PWN::AI::Agent::TurnFinalizer

agent-style post-reply learning. Loop.run returns the user-visible answer first; Reward / Policy / Curriculum keep running off that path. User-visible turn (Loop.run) tools, streaming, TaskSummarizer, final text After the reply is already decided TurnFinalizer.defer -> daemon thread re-attaches the R5 episode snapshot Learning.auto_introspect (critic, Reward.judge, PRM, HER, reflect) Default ON during Loop.run (PWN::Env[:ai][:agent][:defer_introspect]). Direct Learning.auto_introspect calls (specs, cron, tools) stay inline so existing ORM contracts still get a synchronous return value.

## When to use

Call `PWN::AI::Agent::TurnFinalizer` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/turn_finalizer.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::TurnFinalizer.help
PWN::AI::Agent::TurnFinalizer.enter_user_path(opts)
```

## Public methods

- `enter_user_path`
- `leave_user_path`
- `user_path`
- `should_defer`
- `defer`
- `finalize`
- `join_all`
- `pending`
- `arbitrate`
- `evidence_ledger`
- `evidence_satisfied`
- `authors`
- `help`
- `enter_user_path!`
- `evidence_satisfied?`
- `join_all!`
- `leave_user_path!`
- `should_defer?`
- `user_path?`

## Source

`pwn/ai/agent/turn_finalizer.rb`

## Verification

`PWN::AI::Agent::TurnFinalizer.respond_to?(:enter_user_path)` after the
module is loaded. Read the source for parameter names.
