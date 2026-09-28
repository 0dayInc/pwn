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

Read-only Bitcoin Core intelligence. No wallet, signing or broadcast RPCs.

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
- `chain_status`
- `get_block_details`
- `inspect_transaction`
- `inspect_outpoint`
- `mempool_summary`
- `trace_transaction`
- `scan_transactions`
- `get_transactions`
- `scan_address_activity`
- `authors`
- `help`

## Source

`pwn/blockchain/btc.rb`

## Verification

`PWN::Blockchain::BTC.respond_to?(:get_latest_block)` after the
module is loaded. Read the source for parameter names.
