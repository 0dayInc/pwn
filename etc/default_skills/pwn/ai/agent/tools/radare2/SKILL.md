---
name: pwn-ai-agent-tools-radare2
description: Drive PWN::Ai::Agent::Tools::Radare2 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::Radare2
  source: pwn/ai/agent/tools/radare2.rb
---

# PWN::Ai::Agent::Tools::Radare2

Public API for PWN::Ai::Agent::Tools::Radare2.

## When to use

Call `PWN::Ai::Agent::Tools::Radare2` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tools/radare2.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Ai::Agent::Tools::Radare2.help
PWN::Ai::Agent::Tools::Radare2.help(opts)
```

## Public methods

- _(no public class methods parsed)_

## Source

`pwn/ai/agent/tools/radare2.rb`

## Verification

`PWN::Ai::Agent::Tools::Radare2.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
