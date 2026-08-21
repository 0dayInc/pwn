---
name: pwn-reports-htmlfooter
description: Drive PWN::Reports::HTMLFooter from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::HTMLFooter
  source: pwn/reports/html_footer.rb
---

# PWN::Reports::HTMLFooter

This plugin generates the HTML header and includes external JS/CSS libraries for PWN reports.

## When to use

Call `PWN::Reports::HTMLFooter` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/html_footer.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::HTMLFooter.help
PWN::Reports::HTMLFooter.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/reports/html_footer.rb`

## Verification

`PWN::Reports::HTMLFooter.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
