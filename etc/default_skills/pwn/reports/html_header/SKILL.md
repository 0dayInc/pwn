---
name: pwn-reports-htmlheader
description: Drive PWN::Reports::HTMLHeader from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::HTMLHeader
  source: pwn/reports/html_header.rb
---

# PWN::Reports::HTMLHeader

This plugin generates the HTML header and includes external JS/CSS libraries for PWN reports.

## When to use

Call `PWN::Reports::HTMLHeader` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/html_header.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::HTMLHeader.help
PWN::Reports::HTMLHeader.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/reports/html_header.rb`

## Verification

`PWN::Reports::HTMLHeader.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
