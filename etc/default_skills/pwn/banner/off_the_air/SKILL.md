---
name: pwn-banner-offtheair
description: Drive PWN::Banner::OffTheAir from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::OffTheAir
  source: pwn/banner/off_the_air.rb
---

# PWN::Banner::OffTheAir

This plugin processes images into readable text

## When to use

Call `PWN::Banner::OffTheAir` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/off_the_air.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::OffTheAir.help
PWN::Banner::OffTheAir.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/off_the_air.rb`

## Verification

`PWN::Banner::OffTheAir.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
