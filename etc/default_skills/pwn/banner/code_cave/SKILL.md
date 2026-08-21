---
name: pwn-banner-codecave
description: Drive PWN::Banner::CodeCave from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::CodeCave
  source: pwn/banner/code_cave.rb
---

# PWN::Banner::CodeCave

This plugin processes images into readable text

## When to use

Call `PWN::Banner::CodeCave` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/code_cave.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::CodeCave.help
PWN::Banner::CodeCave.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/code_cave.rb`

## Verification

`PWN::Banner::CodeCave.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
