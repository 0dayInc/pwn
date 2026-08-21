---
name: pwn-blockchain-btc
description: Drive PWN::Blockchain::BTC from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Blockchain::BTC
  source: pwn/blockchain/btc.rb
---

# PWN::Blockchain::BTC

This plugin interacts with BitCoin's Blockchain API.

## When to use

Call `PWN::Blockchain::BTC` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/blockchain/btc.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Blockchain::BTC.help
PWN::Blockchain::BTC.get_latest_block(opts)
```

## Public methods

- `get_latest_block`
- `get_block_details`
- `get_transactions`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/blockchain/btc.rb`

## Verification

`PWN::Blockchain::BTC.respond_to?(:get_latest_block)` after the
module is loaded. Read the source for parameter names.
