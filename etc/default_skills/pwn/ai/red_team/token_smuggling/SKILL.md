---
name: pwn-ai-redteam-tokensmuggling
description: Drive PWN::AI::RedTeam::TokenSmuggling from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::TokenSmuggling
  source: pwn/ai/red_team/token_smuggling.rb
---

# PWN::AI::RedTeam::TokenSmuggling

AI RedTeam Module used to attempt encoding-based guardrail bypass (Base64, ROT13, leetspeak, zero-width, homoglyph) to smuggle otherwise-blocked instructions past input filters.

## When to use

Call `PWN::AI::RedTeam::TokenSmuggling` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/token_smuggling.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::TokenSmuggling.help
PWN::AI::RedTeam::TokenSmuggling.scan(opts)
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

`pwn/ai/red_team/token_smuggling.rb`

## Verification

`PWN::AI::RedTeam::TokenSmuggling.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
