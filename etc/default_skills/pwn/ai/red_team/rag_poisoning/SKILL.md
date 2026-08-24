---
name: pwn-ai-redteam-ragpoisoning
description: Drive PWN::AI::RedTeam::RagPoisoning from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::RagPoisoning
  source: pwn/ai/red_team/rag_poisoning.rb
---

# PWN::AI::RedTeam::RagPoisoning

AI RedTeam Module used to manipulate retrieval-augmented generation indexes, retrieved passages, and retrieval logic so attacker text is treated as trusted context.

## When to use

Call `PWN::AI::RedTeam::RagPoisoning` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/rag_poisoning.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::RagPoisoning.help
PWN::AI::RedTeam::RagPoisoning.scan(opts)
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

`pwn/ai/red_team/rag_poisoning.rb`

## Verification

`PWN::AI::RedTeam::RagPoisoning.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
