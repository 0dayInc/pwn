---
name: pwn-plugins-ein
description: Drive PWN::Plugins::EIN from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::EIN
  source: pwn/plugins/ein.rb
---

# PWN::Plugins::EIN

This plugin provides useful employer identification number capabilities

## When to use

Call `PWN::Plugins::EIN` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/ein.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::EIN.help
PWN::Plugins::EIN.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/plugins/ein.rb`

## Verification

`PWN::Plugins::EIN.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
