---
name: pwn-ai-agent-opengoal
description: Drive PWN::AI::Agent::OpenGoal from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::OpenGoal
  source: pwn/ai/agent/open_goal.rb
---

# PWN::AI::Agent::OpenGoal

One unfinished host-work request, persisted so the next pwn-ai activation can continue instead of starting a fresh essay.

## When to use

Call `PWN::AI::Agent::OpenGoal` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/open_goal.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::OpenGoal.help
PWN::AI::Agent::OpenGoal.goal_file(opts)
```

## Public methods

- `goal_file`
- `current`
- `begin`
- `clear`
- `resume`
- `authors`
- `help`
- `begin!`
- `clear!`
- `resume?`

## Source

`pwn/ai/agent/open_goal.rb`

## Verification

`PWN::AI::Agent::OpenGoal.respond_to?(:goal_file)` after the
module is loaded. Read the source for parameter names.
