---
name: pwn-www-paypal
description: Drive PWN::WWW::Paypal from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Paypal
  source: pwn/www/paypal.rb
---

# PWN::WWW::Paypal

This plugin supports paypal.com actions.

## When to use

Call `PWN::WWW::Paypal` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/paypal.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Paypal.help
PWN::WWW::Paypal.open(opts)
```

## Public methods

- `open`
- `signup`
- `login`
- `logout`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/paypal.rb`

## Verification

`PWN::WWW::Paypal.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
