---
name: pwn-ai-agent-confirmation
description: Drive PWN::AI::Agent::Confirmation from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Confirmation
  source: pwn/ai/agent/confirmation.rb
---

# PWN::AI::Agent::Confirmation

Per-engagement ACK for exploit/destructive tool calls (PWN-AI-005 tiers).

## When to use

Call `PWN::AI::Agent::Confirmation` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/confirmation.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Confirmation.help
PWN::AI::Agent::Confirmation.required_bins(opts)
```

## Public methods

- `required_bins`
- `tier`
- `gate`
- `authors`
- `help`

## Source

`pwn/ai/agent/confirmation.rb`

## Verification

`PWN::AI::Agent::Confirmation.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
