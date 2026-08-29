---
name: pwn-plugins-radare2
description: Drive PWN::Plugins::Radare2 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Radare2
  source: pwn/plugins/radare2.rb
---

# PWN::Plugins::Radare2

Persistent r2pipe-style session: open/cmd/cmdj/close plus helpers.

## When to use

Call `PWN::Plugins::Radare2` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/radare2.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Radare2.help
PWN::Plugins::Radare2.required_bins(opts)
```

## Public methods

- `required_bins`
- `open`
- `cmd`
- `cmdj`
- `close`
- `functions`
- `xrefs_to`
- `disasm`
- `strings`
- `imports`
- `sections`
- `binary_info`
- `decompile`
- `authors`
- `help`

## Source

`pwn/plugins/radare2.rb`

## Verification

`PWN::Plugins::Radare2.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
