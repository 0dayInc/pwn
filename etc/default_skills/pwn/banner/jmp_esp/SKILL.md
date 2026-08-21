---
name: pwn-banner-jmpesp
description: Drive PWN::Banner::JmpEsp from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner::JmpEsp
  source: pwn/banner/jmp_esp.rb
---

# PWN::Banner::JmpEsp

This plugin processes images into readable text

## When to use

Call `PWN::Banner::JmpEsp` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner/jmp_esp.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner::JmpEsp.help
PWN::Banner::JmpEsp.get(opts)
```

## Public methods

- `get`
- `authors`
- `help`

## Source

`pwn/banner/jmp_esp.rb`

## Verification

`PWN::Banner::JmpEsp.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
