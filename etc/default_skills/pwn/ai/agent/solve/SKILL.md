---
name: pwn-ai-agent-solve
description: Drive PWN::AI::Agent::Solve from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Solve
  source: pwn/ai/agent/solve.rb
---

# PWN::AI::Agent::Solve

Revision-bound, single-writer team coordinator. Role replies are proposals, never observations. Only host-executed checks can become evidence.

## When to use

Call `PWN::AI::Agent::Solve` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/solve.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Solve.help
PWN::AI::Agent::Solve.apply_patch(opts)
```

## Public methods

- `apply_patch`
- `cleanup_worktree`
- `authors`
- `help`

## Source

`pwn/ai/agent/solve.rb`

## Verification

`PWN::AI::Agent::Solve.respond_to?(:apply_patch)` after the
module is loaded. Read the source for parameter names.
