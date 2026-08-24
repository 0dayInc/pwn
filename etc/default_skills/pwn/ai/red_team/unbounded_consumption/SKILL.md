---
name: pwn-ai-redteam-unboundedconsumption
description: Drive PWN::AI::RedTeam::UnboundedConsumption from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::UnboundedConsumption
  source: pwn/ai/red_team/unbounded_consumption.rb
---

# PWN::AI::RedTeam::UnboundedConsumption

AI RedTeam Module used to probe denial-of-wallet, output explosion, recursive tool-call loops, and model-extraction query floods (OWASP LLM06:2026).

## When to use

Call `PWN::AI::RedTeam::UnboundedConsumption` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/unbounded_consumption.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::UnboundedConsumption.help
PWN::AI::RedTeam::UnboundedConsumption.scan(opts)
```

## Public methods

- `scan`
- `security_references`
- `authors`
- `help`

## References

- `references/security.md` — CWE / NIST mapping
- `references/urls.md` — URLs from source

## Source

`pwn/ai/red_team/unbounded_consumption.rb`

## Verification

`PWN::AI::RedTeam::UnboundedConsumption.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
