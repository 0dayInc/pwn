---
name: pwn-banner-matrix
description: Drive PWN::Banner::Matrix from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::Matrix
  source: pwn/banner/matrix.rb
---

# PWN::Banner::Matrix

This plugin processes images into readable text

## When to use

Call `PWN::Banner::Matrix` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/matrix.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::Matrix.help
PWN::Banner::Matrix.get(opts)
```

## Public methods

- `get`
- `you`
- `authors`
- `help`

## Source

`pwn/banner/matrix.rb`

## Verification

`PWN::Banner::Matrix.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
