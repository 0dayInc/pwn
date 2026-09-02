---
name: pwn-ai-agent-tools-verify
description: Drive PWN::Ai::Agent::Tools::Verify from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::Verify
  source: pwn/ai/agent/tools/verify.rb
---

# PWN::Ai::Agent::Tools::Verify

Public API for PWN::Ai::Agent::Tools::Verify.

## When to use

Call `PWN::Ai::Agent::Tools::Verify` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tools/verify.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Ai::Agent::Tools::Verify.help
PWN::Ai::Agent::Tools::Verify.help(opts)
```

## Public methods

- _(no public class methods parsed)_

## Source

`pwn/ai/agent/tools/verify.rb`

## Verification

`PWN::Ai::Agent::Tools::Verify.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
