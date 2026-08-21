---
name: pwn-plugins-scannablecodes
description: Drive PWN::Plugins::ScannableCodes from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::ScannableCodes
  source: pwn/plugins/scannable_codes.rb
---

# PWN::Plugins::ScannableCodes

This plugin is used to Create Scannable BarCodes and QR Codes

## When to use

Call `PWN::Plugins::ScannableCodes` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/scannable_codes.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::ScannableCodes.help
PWN::Plugins::ScannableCodes.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/plugins/scannable_codes.rb`

## Verification

`PWN::Plugins::ScannableCodes.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
