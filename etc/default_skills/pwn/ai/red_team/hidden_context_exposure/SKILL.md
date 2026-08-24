---
name: pwn-ai-redteam-hiddencontextexposure
description: Drive PWN::AI::RedTeam::HiddenContextExposure from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::HiddenContextExposure
  source: pwn/ai/red_team/hidden_context_exposure.rb
---

# PWN::AI::RedTeam::HiddenContextExposure

AI RedTeam Module used to extract or reconstruct hidden system instructions, tool schemas, refusal logic, and other non-user context (OWASP LLM08:2026). Broader than SystemPromptExtraction.

## When to use

Call `PWN::AI::RedTeam::HiddenContextExposure` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/hidden_context_exposure.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::HiddenContextExposure.help
PWN::AI::RedTeam::HiddenContextExposure.scan(opts)
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

`pwn/ai/red_team/hidden_context_exposure.rb`

## Verification

`PWN::AI::RedTeam::HiddenContextExposure.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
