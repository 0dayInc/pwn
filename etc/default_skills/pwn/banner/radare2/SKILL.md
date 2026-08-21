---
name: pwn-banner-radare2
description: Drive PWN::Banner::Radare2 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::Radare2
  source: pwn/banner/radare2.rb
---

# PWN::Banner::Radare2

This plugin processes images into readable text

## When to use

Call `PWN::Banner::Radare2` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/radare2.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::Radare2.help
PWN::Banner::Radare2.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/radare2.rb`

## Verification

`PWN::Banner::Radare2.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
