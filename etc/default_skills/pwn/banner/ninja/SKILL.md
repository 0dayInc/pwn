---
name: pwn-banner-ninja
description: Drive PWN::Banner::Ninja from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::Ninja
  source: pwn/banner/ninja.rb
---

# PWN::Banner::Ninja

This plugin processes images into readable text

## When to use

Call `PWN::Banner::Ninja` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/ninja.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::Ninja.help
PWN::Banner::Ninja.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/ninja.rb`

## Verification

`PWN::Banner::Ninja.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
