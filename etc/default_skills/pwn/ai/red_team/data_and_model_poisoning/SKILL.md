---
name: pwn-ai-redteam-dataandmodelpoisoning
description: Drive PWN::AI::RedTeam::DataAndModelPoisoning from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::DataAndModelPoisoning
  source: pwn/ai/red_team/data_and_model_poisoning.rb
---

# PWN::AI::RedTeam::DataAndModelPoisoning

AI RedTeam Module used to evaluate training, fine-tuning, and retrieval corpora for poison, sleeper triggers, and fine-tuning subversion (OWASP LLM05:2026).

## When to use

Call `PWN::AI::RedTeam::DataAndModelPoisoning` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/data_and_model_poisoning.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::DataAndModelPoisoning.help
PWN::AI::RedTeam::DataAndModelPoisoning.scan(opts)
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

`pwn/ai/red_team/data_and_model_poisoning.rb`

## Verification

`PWN::AI::RedTeam::DataAndModelPoisoning.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
