---
name: pwn-blockchain-eth
description: Drive PWN::Blockchain::ETH from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Blockchain::ETH
  source: pwn/blockchain/eth.rb
---

# PWN::Blockchain::ETH

This plugin interacts with BitCoin's Blockchain API.

## When to use

Call `PWN::Blockchain::ETH` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/blockchain/eth.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Blockchain::ETH.help
PWN::Blockchain::ETH.get_latest_block(opts)
```

## Public methods

- `get_latest_block`
- `get_block_details`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/blockchain/eth.rb`

## Verification

`PWN::Blockchain::ETH.respond_to?(:get_latest_block)` after the
module is loaded. Read the source for parameter names.
