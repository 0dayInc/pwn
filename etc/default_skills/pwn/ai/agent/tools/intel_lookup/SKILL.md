---
name: pwn-ai-agent-tools-intellookup
description: Drive PWN::Ai::Agent::Tools::IntelLookup from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::IntelLookup
  source: pwn/ai/agent/tools/intel_lookup.rb
---

# PWN::Ai::Agent::Tools::IntelLookup

Public API for PWN::Ai::Agent::Tools::IntelLookup.

## When to use

Call `PWN::Ai::Agent::Tools::IntelLookup` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tools/intel_lookup.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Ai::Agent::Tools::IntelLookup.help
PWN::Ai::Agent::Tools::IntelLookup.help(opts)
```

## Public methods

- _(no public class methods parsed)_

## Source

`pwn/ai/agent/tools/intel_lookup.rb`

## Verification

`PWN::Ai::Agent::Tools::IntelLookup.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
