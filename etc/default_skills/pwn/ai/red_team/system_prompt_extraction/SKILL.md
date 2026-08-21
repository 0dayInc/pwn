---
name: pwn-ai-redteam-systempromptextraction
description: Drive PWN::AI::RedTeam::SystemPromptExtraction from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::SystemPromptExtraction
  source: pwn/ai/red_team/system_prompt_extraction.rb
---

# PWN::AI::RedTeam::SystemPromptExtraction

AI RedTeam Module used to attempt extraction / leakage of the target LLM's hidden system prompt, developer instructions, or guardrail configuration.

## When to use

Call `PWN::AI::RedTeam::SystemPromptExtraction` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/system_prompt_extraction.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::SystemPromptExtraction.help
PWN::AI::RedTeam::SystemPromptExtraction.scan(opts)
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

`pwn/ai/red_team/system_prompt_extraction.rb`

## Verification

`PWN::AI::RedTeam::SystemPromptExtraction.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
