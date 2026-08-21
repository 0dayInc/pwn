---
name: pwn-ai-redteam-promptinjection
description: Drive PWN::AI::RedTeam::PromptInjection from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::PromptInjection
  source: pwn/ai/red_team/prompt_injection.rb
---

# PWN::AI::RedTeam::PromptInjection

AI RedTeam Module used to identify direct & indirect prompt injection weaknesses in a target LLM by attempting to override, append to, or subvert its system instructions.

## When to use

Call `PWN::AI::RedTeam::PromptInjection` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/prompt_injection.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::PromptInjection.help
PWN::AI::RedTeam::PromptInjection.scan(opts)
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

`pwn/ai/red_team/prompt_injection.rb`

## Verification

`PWN::AI::RedTeam::PromptInjection.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
