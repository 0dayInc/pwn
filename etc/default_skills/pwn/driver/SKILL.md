---
name: pwn
description: Drive PWN from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN
  source: pwn/driver.rb
---

# PWN

Public API for PWN.

## When to use

Call `PWN` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/driver.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN.help
PWN.help(opts)
```

## Public methods

- `authors`
- `help`

## Source

`pwn/driver.rb`

## Verification

`PWN.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
