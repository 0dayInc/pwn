---
name: pwn-plugins-ghidra
description: Drive PWN::Plugins::Ghidra from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Ghidra
  source: pwn/plugins/ghidra.rb
---

# PWN::Plugins::Ghidra

Headless Ghidra analyzeHeadless wrapper with r2 fallback.

## When to use

Call `PWN::Plugins::Ghidra` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/ghidra.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Ghidra.help
PWN::Plugins::Ghidra.required_bins(opts)
```

## Public methods

- `required_bins`
- `analyze`
- `decompile`
- `authors`
- `help`

## Source

`pwn/plugins/ghidra.rb`

## Verification

`PWN::Plugins::Ghidra.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
