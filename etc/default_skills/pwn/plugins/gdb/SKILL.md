---
name: pwn-plugins-gdb
description: Drive PWN::Plugins::GDB from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::GDB
  source: pwn/plugins/gdb.rb
---

# PWN::Plugins::GDB

gdb/MI batch driver: run-to-crash, registers, mitigations, core dumps.

## When to use

Call `PWN::Plugins::GDB` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/gdb.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::GDB.help
PWN::Plugins::GDB.required_bins(opts)
```

## Public methods

- `required_bins`
- `batch`
- `run_to_crash`
- `registers`
- `mitigations`
- `core`
- `breakpoints`
- `crash_info`
- `debug_session`
- `ptrace_preflight`
- `authors`
- `help`

## Source

`pwn/plugins/gdb.rb`

## Verification

`PWN::Plugins::GDB.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
