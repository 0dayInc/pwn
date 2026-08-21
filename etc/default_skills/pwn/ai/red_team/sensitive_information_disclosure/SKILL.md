---
name: pwn-ai-redteam-sensitiveinformationdisclosure
description: Drive PWN::AI::RedTeam::SensitiveInformationDisclosure from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::SensitiveInformationDisclosure
  source: pwn/ai/red_team/sensitive_information_disclosure.rb
---

# PWN::AI::RedTeam::SensitiveInformationDisclosure

AI RedTeam Module used to probe a target LLM for training-data memorization, PII leakage, credential regurgitation, and other sensitive information disclosure failures.

## When to use

Call `PWN::AI::RedTeam::SensitiveInformationDisclosure` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/sensitive_information_disclosure.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::SensitiveInformationDisclosure.help
PWN::AI::RedTeam::SensitiveInformationDisclosure.scan(opts)
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

`pwn/ai/red_team/sensitive_information_disclosure.rb`

## Verification

`PWN::AI::RedTeam::SensitiveInformationDisclosure.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
