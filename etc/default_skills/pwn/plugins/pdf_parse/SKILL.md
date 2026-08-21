---
name: pwn-plugins-pdfparse
description: Drive PWN::Plugins::PDFParse from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::PDFParse
  source: pwn/plugins/pdf_parse.rb
---

# PWN::Plugins::PDFParse

This plugin is used for parsing and interacting with PDF files

## When to use

Call `PWN::Plugins::PDFParse` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/pdf_parse.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::PDFParse.help
PWN::Plugins::PDFParse.read_text(opts)
```

## Public methods

- `read_text`
- `authors`
- `help`

## Source

`pwn/plugins/pdf_parse.rb`

## Verification

`PWN::Plugins::PDFParse.respond_to?(:read_text)` after the
module is loaded. Read the source for parameter names.
