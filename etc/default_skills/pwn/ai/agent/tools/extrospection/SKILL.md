---
name: pwn-ai-agent-tools-extrospection
description: Drive PWN::Ai::Agent::Tools::Extrospection from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::Extrospection
  source: pwn/ai/agent/tools/extrospection.rb
---

# PWN::Ai::Agent::Tools::Extrospection

Public API for PWN::Ai::Agent::Tools::Extrospection.

## When to use

Call `PWN::Ai::Agent::Tools::Extrospection` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tools/extrospection.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Ai::Agent::Tools::Extrospection.help
PWN::Ai::Agent::Tools::Extrospection.help(opts)
```

## Public methods

- _(no public class methods parsed)_

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/agent/tools/extrospection.rb`

## Verification

`PWN::Ai::Agent::Tools::Extrospection.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
