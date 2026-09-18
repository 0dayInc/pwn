---
name: pwn-plugins-rop
description: Drive PWN::Plugins::ROP from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::ROP
  source: pwn/plugins/rop.rb
---

# PWN::Plugins::ROP

Read-only gadget enumeration; clobbers are conservative syntactic estimates.

## When to use

Call `PWN::Plugins::ROP` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/rop.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::ROP.help
PWN::Plugins::ROP.required_bins(opts)
```

## Public methods

- `required_bins`
- `parse`
- `gadgets`
- `filter`
- `authors`
- `help`

## Source

`pwn/plugins/rop.rb`

## Verification

`PWN::Plugins::ROP.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
