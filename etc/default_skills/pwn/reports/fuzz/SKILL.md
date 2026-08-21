---
name: pwn-reports-fuzz
description: Drive PWN::Reports::Fuzz from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::Fuzz
  source: pwn/reports/fuzz.rb
---

# PWN::Reports::Fuzz

This plugin generates Fuzz results from PWN::Plugins::Fuzz. Two files are created, a JSON file containing all of the Fuzz results and an HTML file which is essentially the UI for the JSON file.

## When to use

Call `PWN::Reports::Fuzz` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/fuzz.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::Fuzz.help
PWN::Reports::Fuzz.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/reports/fuzz.rb`

## Verification

`PWN::Reports::Fuzz.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
