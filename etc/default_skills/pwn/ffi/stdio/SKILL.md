---
name: pwn-ffi-stdio
description: Drive PWN::FFI::Stdio from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::Stdio
  source: pwn/ffi/stdio.rb
---

# PWN::FFI::Stdio

This plugin is a wrapper for the standard I/O functions in libc.

## When to use

Call `PWN::FFI::Stdio` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/stdio.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::Stdio.help
PWN::FFI::Stdio.available(opts)
```

## Public methods

- `available`
- `authors`
- `help`

## Source

`pwn/ffi/stdio.rb`

## Verification

`PWN::FFI::Stdio.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
