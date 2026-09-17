---
name: pwn-ffi-capstone
description: Drive PWN::FFI::Capstone from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::Capstone
  source: pwn/ffi/capstone.rb
---

# PWN::FFI::Capstone

Thin libcapstone disassembler.

## When to use

Call `PWN::FFI::Capstone` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/capstone.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::Capstone.help
PWN::FFI::Capstone.available(opts)
```

## Public methods

- `available`
- `disassemble`
- `authors`
- `help`
- `available?`
- `cs_close`
- `cs_disasm`
- `cs_free`
- `cs_open`
- `load_error`

## Source

`pwn/ffi/capstone.rb`

## Verification

`PWN::FFI::Capstone.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
