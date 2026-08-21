---
name: pwn-ai-redteam-excessiveagency
description: Drive PWN::AI::RedTeam::ExcessiveAgency from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::ExcessiveAgency
  source: pwn/ai/red_team/excessive_agency.rb
---

# PWN::AI::RedTeam::ExcessiveAgency

AI RedTeam Module used to determine if a target LLM can be coerced into invoking tools, plugins, or external actions outside of its intended authorization scope (excessive agency).

## When to use

Call `PWN::AI::RedTeam::ExcessiveAgency` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/excessive_agency.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::ExcessiveAgency.help
PWN::AI::RedTeam::ExcessiveAgency.scan(opts)
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

`pwn/ai/red_team/excessive_agency.rb`

## Verification

`PWN::AI::RedTeam::ExcessiveAgency.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
