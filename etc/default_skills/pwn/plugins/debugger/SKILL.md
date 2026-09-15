---
name: pwn-plugins-debugger
description: Drive PWN::Plugins::Debugger from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Debugger
  source: pwn/plugins/debugger.rb
---

# PWN::Plugins::Debugger

Structured GDB/MI driver with a handle registry that survives pwn_eval.

## When to use

Call `PWN::Plugins::Debugger` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/debugger.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Debugger.help
PWN::Plugins::Debugger.required_bins(opts)
```

## Public methods

- `required_bins`
- `launch`
- `attach`
- `run`
- `break`
- `continue`
- `step`
- `read_mem`
- `write_mem`
- `regs`
- `backtrace`
- `checksec`
- `cyclic`
- `cyclic_find`
- `to_pwntools_offsets`
- `close`
- `authors`
- `help`

## Source

`pwn/plugins/debugger.rb`

## Verification

`PWN::Plugins::Debugger.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
