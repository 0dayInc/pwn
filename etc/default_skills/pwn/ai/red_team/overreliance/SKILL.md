---
name: pwn-ai-redteam-overreliance
description: Drive PWN::AI::RedTeam::Overreliance from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::Overreliance
  source: pwn/ai/red_team/overreliance.rb
---

# PWN::AI::RedTeam::Overreliance

AI RedTeam Module used to probe a target LLM for confident hallucination / misinformation (overreliance) by asking loaded, false-premise, and fabricated-citation questions.

## When to use

Call `PWN::AI::RedTeam::Overreliance` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/overreliance.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::Overreliance.help
PWN::AI::RedTeam::Overreliance.scan(opts)
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

`pwn/ai/red_team/overreliance.rb`

## Verification

`PWN::AI::RedTeam::Overreliance.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
