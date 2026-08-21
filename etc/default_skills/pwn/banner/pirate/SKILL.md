---
name: pwn-banner-pirate
description: Drive PWN::Banner::Pirate from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::Pirate
  source: pwn/banner/pirate.rb
---

# PWN::Banner::Pirate

This plugin processes images into readable text

## When to use

Call `PWN::Banner::Pirate` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/pirate.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::Pirate.help
PWN::Banner::Pirate.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/pirate.rb`

## Verification

`PWN::Banner::Pirate.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
