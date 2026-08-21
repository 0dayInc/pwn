---
name: pwn-ai-agent-result
description: Drive PWN::AI::Agent::Result from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Result
  source: pwn/ai/agent/result.rb
---

# PWN::AI::Agent::Result

Conditioning applied to every tool result before it re-enters the conversation as a role:'tool' message: hard size cap + credential redaction. Keeps the context window bounded and avoids leaking PWN::Env credentials back into the model.

## When to use

Call `PWN::AI::Agent::Result` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/result.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Result.help
PWN::AI::Agent::Result.condition(opts)
```

## Public methods

- `condition`
- `default_max`
- `redact`
- `authors`
- `help`

## Source

`pwn/ai/agent/result.rb`

## Verification

`PWN::AI::Agent::Result.respond_to?(:condition)` after the
module is loaded. Read the source for parameter names.
