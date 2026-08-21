---
name: pwn-banner-bubble
description: Drive PWN::Banner::Bubble from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::Bubble
  source: pwn/banner/bubble.rb
---

# PWN::Banner::Bubble

This plugin processes images into readable text

## When to use

Call `PWN::Banner::Bubble` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/bubble.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::Bubble.help
PWN::Banner::Bubble.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/bubble.rb`

## Verification

`PWN::Banner::Bubble.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
