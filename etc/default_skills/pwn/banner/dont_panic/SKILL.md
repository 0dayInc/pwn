---
name: pwn-banner-dontpanic
description: Drive PWN::Banner::DontPanic from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::DontPanic
  source: pwn/banner/dont_panic.rb
---

# PWN::Banner::DontPanic

This plugin processes images into readable text

## When to use

Call `PWN::Banner::DontPanic` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/dont_panic.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::DontPanic.help
PWN::Banner::DontPanic.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/dont_panic.rb`

## Verification

`PWN::Banner::DontPanic.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
