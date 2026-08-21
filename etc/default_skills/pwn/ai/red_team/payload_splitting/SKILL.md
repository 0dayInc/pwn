---
name: pwn-ai-redteam-payloadsplitting
description: Drive PWN::AI::RedTeam::PayloadSplitting from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::PayloadSplitting
  source: pwn/ai/red_team/payload_splitting.rb
---

# PWN::AI::RedTeam::PayloadSplitting

AI RedTeam Module used to attempt multi-part / fragmented payload delivery where individually-benign fragments are reassembled by the target LLM into a malicious instruction.

## When to use

Call `PWN::AI::RedTeam::PayloadSplitting` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/payload_splitting.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::PayloadSplitting.help
PWN::AI::RedTeam::PayloadSplitting.scan(opts)
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

`pwn/ai/red_team/payload_splitting.rb`

## Verification

`PWN::AI::RedTeam::PayloadSplitting.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
