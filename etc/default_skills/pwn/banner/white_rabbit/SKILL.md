---
name: pwn-banner-whiterabbit
description: Drive PWN::Banner::WhiteRabbit from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::WhiteRabbit
  source: pwn/banner/white_rabbit.rb
---

# PWN::Banner::WhiteRabbit

This plugin processes images into readable text

## When to use

Call `PWN::Banner::WhiteRabbit` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/white_rabbit.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::WhiteRabbit.help
PWN::Banner::WhiteRabbit.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/white_rabbit.rb`

## Verification

`PWN::Banner::WhiteRabbit.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
