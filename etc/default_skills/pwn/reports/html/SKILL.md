---
name: pwn-reports-html
description: Drive PWN::Reports::HTML from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::HTML
  source: pwn/reports/html.rb
---

# PWN::Reports::HTML

Generic HTML report writer for pentest / findings payloads.

## When to use

Call `PWN::Reports::HTML` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/html.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::HTML.help
PWN::Reports::HTML.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/reports/html.rb`

## Verification

`PWN::Reports::HTML.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
