---
name: pwn-banner-anon
description: Drive PWN::Banner::Anon from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::Anon
  source: pwn/banner/anon.rb
---

# PWN::Banner::Anon

This plugin processes images into readable text

## When to use

Call `PWN::Banner::Anon` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/anon.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::Anon.help
PWN::Banner::Anon.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/anon.rb`

## Verification

`PWN::Banner::Anon.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
