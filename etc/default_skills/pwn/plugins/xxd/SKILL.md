---
name: pwn-plugins-xxd
description: Drive PWN::Plugins::XXD from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::XXD
  source: pwn/plugins/xxd.rb
---

# PWN::Plugins::XXD

This module provides the abilty to dump binaries in hex format

## When to use

Call `PWN::Plugins::XXD` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/xxd.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::XXD.help
PWN::Plugins::XXD.dump(opts)
```

## Public methods

- `dump`
- `fill_range_w_byte`
- `calc_addr_offset`
- `reverse_hex_string`
- `reverse_dump`
- `authors`
- `help`

## Source

`pwn/plugins/xxd.rb`

## Verification

`PWN::Plugins::XXD.respond_to?(:dump)` after the
module is loaded. Read the source for parameter names.
