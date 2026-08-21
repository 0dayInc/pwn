---
name: pwn-ai-redteam-jailbreak
description: Drive PWN::AI::RedTeam::Jailbreak from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::Jailbreak
  source: pwn/ai/red_team/jailbreak.rb
---

# PWN::AI::RedTeam::Jailbreak

AI RedTeam Module used to attempt classic jailbreak / persona hijack techniques (DAN, Developer-Mode, grandma, role-play escape) against a target LLM to determine if safety alignment can be bypassed.

## When to use

Call `PWN::AI::RedTeam::Jailbreak` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/jailbreak.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::Jailbreak.help
PWN::AI::RedTeam::Jailbreak.scan(opts)
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

`pwn/ai/red_team/jailbreak.rb`

## Verification

`PWN::AI::RedTeam::Jailbreak.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
