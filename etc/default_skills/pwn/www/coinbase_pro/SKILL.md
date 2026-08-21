---
name: pwn-www-coinbasepro
description: Drive PWN::WWW::CoinbasePro from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::CoinbasePro
  source: pwn/www/coinbase_pro.rb
---

# PWN::WWW::CoinbasePro

This plugin supports tradingview.com actions.

## When to use

Call `PWN::WWW::CoinbasePro` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/coinbase_pro.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::CoinbasePro.help
PWN::WWW::CoinbasePro.open(opts)
```

## Public methods

- `open`
- `login`
- `logout`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/coinbase_pro.rb`

## Verification

`PWN::WWW::CoinbasePro.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
