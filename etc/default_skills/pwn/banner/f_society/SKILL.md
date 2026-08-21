---
name: pwn-banner-fsociety
description: Drive PWN::Banner::FSociety from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::FSociety
  source: pwn/banner/f_society.rb
---

# PWN::Banner::FSociety

This plugin processes images into readable text

## When to use

Call `PWN::Banner::FSociety` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/f_society.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::FSociety.help
PWN::Banner::FSociety.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/f_society.rb`

## Verification

`PWN::Banner::FSociety.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
