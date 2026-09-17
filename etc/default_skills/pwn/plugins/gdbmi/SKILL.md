---
name: pwn-plugins-gdbmi
description: Drive PWN::Plugins::GDBMI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::GDBMI
  source: pwn/plugins/gdbmi.rb
---

# PWN::Plugins::GDBMI

Plugin namespace. GDBMi is a requested alias of GDBMI.

## When to use

Call `PWN::Plugins::GDBMI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/gdbmi.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::GDBMI.help
PWN::Plugins::GDBMI.required_bins(opts)
```

## Public methods

- `required_bins`
- `open`
- `session`
- `close`
- `break`
- `run`
- `continue`
- `registers`
- `read_mem`
- `read_memory`
- `backtrace`
- `step`
- `checksec`
- `run_to_crash`
- `mi`
- `authors`
- `help`

## Source

`pwn/plugins/gdbmi.rb`

## Verification

`PWN::Plugins::GDBMI.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
