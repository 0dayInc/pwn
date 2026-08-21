---
name: pwn-plugins-creditcard
description: Drive PWN::Plugins::CreditCard from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::CreditCard
  source: pwn/plugins/credit_card.rb
---

# PWN::Plugins::CreditCard

This plugin provides useful credit card capabilities

## When to use

Call `PWN::Plugins::CreditCard` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/credit_card.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::CreditCard.help
PWN::Plugins::CreditCard.list_types(opts)
```

## Public methods

- `list_types`
- `generate`
- `type`
- `authors`
- `help`

## Source

`pwn/plugins/credit_card.rb`

## Verification

`PWN::Plugins::CreditCard.respond_to?(:list_types)` after the
module is loaded. Read the source for parameter names.
