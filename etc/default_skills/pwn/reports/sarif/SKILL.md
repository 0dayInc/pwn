---
name: pwn-reports-sarif
description: Drive PWN::Reports::SARIF from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::SARIF
  source: pwn/reports/sarif.rb
---

# PWN::Reports::SARIF

SARIF 2.1.0 writer for finding export.

## When to use

Call `PWN::Reports::SARIF` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/sarif.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::SARIF.help
PWN::Reports::SARIF.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/reports/sarif.rb`

## Verification

`PWN::Reports::SARIF.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
