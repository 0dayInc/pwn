---
name: pwn-reports
description: Drive PWN::Reports from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports
  source: pwn/reports.rb
---

# PWN::Reports

This file, using the autoload directive loads Report modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::Reports` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports.help
PWN::Reports.help(opts)
```

## Public methods

- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/reports.rb`

## Verification

`PWN::Reports.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
