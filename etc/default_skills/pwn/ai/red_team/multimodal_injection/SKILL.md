---
name: pwn-ai-redteam-multimodalinjection
description: Drive PWN::AI::RedTeam::MultimodalInjection from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::MultimodalInjection
  source: pwn/ai/red_team/multimodal_injection.rb
---

# PWN::AI::RedTeam::MultimodalInjection

AI RedTeam Module used to hide instructions in images, audio, video, or steganographic encodings that a multimodal encoder still obeys (OWASP LLM01:2026 multimodal).

## When to use

Call `PWN::AI::RedTeam::MultimodalInjection` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/multimodal_injection.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::MultimodalInjection.help
PWN::AI::RedTeam::MultimodalInjection.scan(opts)
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

`pwn/ai/red_team/multimodal_injection.rb`

## Verification

`PWN::AI::RedTeam::MultimodalInjection.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
