---
name: pwn-banner-cheshire
description: Drive PWN::Banner::Cheshire from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::Cheshire
  source: pwn/banner/cheshire.rb
---

# PWN::Banner::Cheshire

This plugin processes images into readable text

## When to use

Call `PWN::Banner::Cheshire` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/cheshire.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::Cheshire.help
PWN::Banner::Cheshire.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/cheshire.rb`

## Verification

`PWN::Banner::Cheshire.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
