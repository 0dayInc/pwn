---
name: pwn-ffi-keystone
description: Drive PWN::FFI::Keystone from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::Keystone
  source: pwn/ffi/keystone.rb
---

# PWN::FFI::Keystone

Thin libkeystone assembler.

## When to use

Call `PWN::FFI::Keystone` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/keystone.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::Keystone.help
PWN::FFI::Keystone.available(opts)
```

## Public methods

- `available`
- `assemble`
- `authors`
- `help`
- `available?`
- `load_error`

## Source

`pwn/ffi/keystone.rb`

## Verification

`PWN::FFI::Keystone.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
