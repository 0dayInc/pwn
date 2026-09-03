---
name: pwn-ai-agent-engagement
description: Drive PWN::AI::Agent::Engagement from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Engagement
  source: pwn/ai/agent/engagement.rb
---

# PWN::AI::Agent::Engagement

First-class engagement scope, RoE, and findings pointer.

## When to use

Call `PWN::AI::Agent::Engagement` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/engagement.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Engagement.help
PWN::AI::Agent::Engagement.open(opts)
```

## Public methods

- `open`
- `close`
- `status`
- `current_name`
- `in_scope`
- `deny_if_out_of_scope`
- `authors`
- `help`
- `in_scope?`

## Source

`pwn/ai/agent/engagement.rb`

## Verification

`PWN::AI::Agent::Engagement.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
