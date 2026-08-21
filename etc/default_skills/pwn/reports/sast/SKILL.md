---
name: pwn-reports-sast
description: Drive PWN::Reports::SAST from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::SAST
  source: pwn/reports/sast.rb
---

# PWN::Reports::SAST

This plugin generates the Static Code Anti-Pattern Matching Analysis results within the root of a given source repo. Two files are created, a JSON file containing all of the SAST results and an HTML file which is essentially the UI for the JSON file.

## When to use

Call `PWN::Reports::SAST` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/sast.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::SAST.help
PWN::Reports::SAST.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/reports/sast.rb`

## Verification

`PWN::Reports::SAST.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
