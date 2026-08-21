---
name: pwn-banner-radare2ai
description: Drive PWN::Banner::Radare2AI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::Radare2AI
  source: pwn/banner/radare2_ai.rb
---

# PWN::Banner::Radare2AI

This plugin processes images into readable text

## When to use

Call `PWN::Banner::Radare2AI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/radare2_ai.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::Radare2AI.help
PWN::Banner::Radare2AI.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/banner/radare2_ai.rb`

## Verification

`PWN::Banner::Radare2AI.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
