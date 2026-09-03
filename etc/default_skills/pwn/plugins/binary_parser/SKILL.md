---
name: pwn-plugins-binaryparser
description: Drive PWN::Plugins::BinaryParser from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BinaryParser
  source: pwn/plugins/binary_parser.rb
---

# PWN::Plugins::BinaryParser

ELF/PE/Mach-O headers, sections, symbols, imports/exports, relocations via Metasm loaders.

## When to use

Call `PWN::Plugins::BinaryParser` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/binary_parser.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BinaryParser.help
PWN::Plugins::BinaryParser.required_bins(opts)
```

## Public methods

- `required_bins`
- `load_exe`
- `info`
- `sections`
- `symbols`
- `imports`
- `exports`
- `relocations`
- `triage`
- `diff`
- `authors`
- `help`

## Source

`pwn/plugins/binary_parser.rb`

## Verification

`PWN::Plugins::BinaryParser.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
