---
name: pwn-plugins-ocr
description: Drive PWN::Plugins::OCR from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::OCR
  source: pwn/plugins/ocr.rb
---

# PWN::Plugins::OCR

This plugin processes images into readable text

## When to use

Call `PWN::Plugins::OCR` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/ocr.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::OCR.help
PWN::Plugins::OCR.process(opts)
```

## Public methods

- `process`
- `authors`
- `help`

## Source

`pwn/plugins/ocr.rb`

## Verification

`PWN::Plugins::OCR.respond_to?(:process)` after the
module is loaded. Read the source for parameter names.
