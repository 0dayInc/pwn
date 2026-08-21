---
name: pwn-banner-forkbomb
description: Drive PWN::Banner::ForkBomb from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::ForkBomb
  source: pwn/banner/fork_bomb.rb
---

# PWN::Banner::ForkBomb

This plugin processes images into readable text

## When to use

Call `PWN::Banner::ForkBomb` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/fork_bomb.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::ForkBomb.help
PWN::Banner::ForkBomb.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/fork_bomb.rb`

## Verification

`PWN::Banner::ForkBomb.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
