---
name: pwn-ai-agent-mission
description: Drive PWN::AI::Agent::Mission from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Mission
  source: pwn/ai/agent/mission.rb
---

# PWN::AI::Agent::Mission

Durable mission ledger. A killed turn resumes the bound DAG instead of re-inferring a plan.

## When to use

Call `PWN::AI::Agent::Mission` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/mission.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Mission.help
PWN::AI::Agent::Mission.begin(opts)
```

## Public methods

- `begin`
- `plan`
- `current`
- `active`
- `active_id`
- `bind_run`
- `resume_run`
- `done`
- `complete`
- `note_finding`
- `note_loot`
- `note_technique`
- `note_job`
- `note_shell_exception`
- `record_lost`
- `recover`
- `busy`
- `ledger_text`
- `report_text`
- `authors`
- `help`
- `begin!`
- `bind_run!`
- `busy?`
- `complete!`
- `done?`
- `note_finding!`
- `note_job!`
- `note_loot!`
- `note_shell_exception!`
- `note_technique!`
- `plan!`
- `recover!`

## Source

`pwn/ai/agent/mission.rb`

## Verification

`PWN::AI::Agent::Mission.respond_to?(:begin)` after the
module is loaded. Read the source for parameter names.
