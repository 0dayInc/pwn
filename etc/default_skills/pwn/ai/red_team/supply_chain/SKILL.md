---
name: pwn-ai-redteam-supplychain
description: Drive PWN::AI::RedTeam::SupplyChain from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::SupplyChain
  source: pwn/ai/red_team/supply_chain.rb
---

# PWN::AI::RedTeam::SupplyChain

AI RedTeam Module used to probe LLM application supply-chain trust: tampered model artifacts, slopsquatted packages, MCP tool packages, and unsigned adapters (OWASP LLM04:2026).

## When to use

Call `PWN::AI::RedTeam::SupplyChain` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/supply_chain.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::SupplyChain.help
PWN::AI::RedTeam::SupplyChain.scan(opts)
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

`pwn/ai/red_team/supply_chain.rb`

## Verification

`PWN::AI::RedTeam::SupplyChain.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
