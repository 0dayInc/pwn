---
name: pwn-reports-csv
description: Drive PWN::Reports::CSV from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::CSV
  source: pwn/reports/csv.rb
---

# PWN::Reports::CSV

Generic CSV report writer for pentest / findings payloads.

## When to use

Call `PWN::Reports::CSV` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/csv.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::CSV.help
PWN::Reports::CSV.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/reports/csv.rb`

## Verification

`PWN::Reports::CSV.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
