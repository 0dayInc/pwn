---
name: pwn-reports-airedteam
description: Drive PWN::Reports::AIRedTeam from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::AIRedTeam
  source: pwn/reports/ai_red_team.rb
---

# PWN::Reports::AIRedTeam

This plugin generates the AI Red Team / LLM Adversarial Analysis results within the root of a given output directory. Two files are created, a JSON file containing all of the AI RedTeam results and an HTML file which is essentially the UI for the JSON file.

## When to use

Call `PWN::Reports::AIRedTeam` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/ai_red_team.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::AIRedTeam.help
PWN::Reports::AIRedTeam.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/reports/ai_red_team.rb`

## Verification

`PWN::Reports::AIRedTeam.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
