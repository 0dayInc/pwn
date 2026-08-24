---
name: pwn-ai-redteam-memorypoisoning
description: Drive PWN::AI::RedTeam::MemoryPoisoning from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::MemoryPoisoning
  source: pwn/ai/red_team/memory_poisoning.rb
---

# PWN::AI::RedTeam::MemoryPoisoning

AI RedTeam Module used to persist attacker instructions in long-term agent memory, hosted memory services, or cross-session state so later turns inherit the compromise.

## When to use

Call `PWN::AI::RedTeam::MemoryPoisoning` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/memory_poisoning.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::MemoryPoisoning.help
PWN::AI::RedTeam::MemoryPoisoning.scan(opts)
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

`pwn/ai/red_team/memory_poisoning.rb`

## Verification

`PWN::AI::RedTeam::MemoryPoisoning.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
