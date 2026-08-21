---
name: pwn-plugins-assembly
description: Drive PWN::Plugins::Assembly from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Assembly
  source: pwn/plugins/assembly.rb
---

# PWN::Plugins::Assembly

This plugin provides methods for converting between hex escaped opcodes and assembly instructions using the Metasm library.

## When to use

Call `PWN::Plugins::Assembly` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/assembly.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Assembly.help
PWN::Plugins::Assembly.opcodes_to_asm(opts)
```

## Public methods

- `opcodes_to_asm`
- `asm_to_opcodes`
- `list_supported_archs`
- `authors`
- `help`

## Source

`pwn/plugins/assembly.rb`

## Verification

`PWN::Plugins::Assembly.respond_to?(:opcodes_to_asm)` after the
module is loaded. Read the source for parameter names.
