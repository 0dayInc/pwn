---
name: pwn-reports-pdf
description: Drive PWN::Reports::PDF from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::PDF
  source: pwn/reports/pdf.rb
---

# PWN::Reports::PDF

Generic PDF report writer for pentest / findings payloads. Emits a minimal PDF 1.4 document (no wkhtmltopdf).

## When to use

Call `PWN::Reports::PDF` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/pdf.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::PDF.help
PWN::Reports::PDF.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/reports/pdf.rb`

## Verification

`PWN::Reports::PDF.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
