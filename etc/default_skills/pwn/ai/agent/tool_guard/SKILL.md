---
name: pwn-ai-agent-toolguard
description: Drive PWN::AI::Agent::ToolGuard from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::ToolGuard
  source: pwn/ai/agent/tool_guard.rb
---

# PWN::AI::Agent::ToolGuard

Shared pre-dispatch guards for the two high-volume runtime tools (shell / pwn_eval). Rejects placeholder payloads, aliases wrong schema keys, and names the shell that will actually run the command.

## When to use

Call `PWN::AI::Agent::ToolGuard` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tool_guard.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::ToolGuard.help
PWN::AI::Agent::ToolGuard.present(opts)
```

## Public methods

- `present`
- `placeholder`
- `bashism`
- `shell_bash`
- `shell_name`
- `coerce_args`
- `invalid_payload`
- `host_load`
- `deadline_s`
- `reset_timeout_budget`
- `mutation_count`
- `payload_spent`
- `note_timeout`
- `next_timeout`
- `timeout_lesson`
- `timeout_result`
- `timeout_prior_count`
- `authors`
- `help`

## Source

`pwn/ai/agent/tool_guard.rb`

## Verification

`PWN::AI::Agent::ToolGuard.respond_to?(:present)` after the
module is loaded. Read the source for parameter names.
