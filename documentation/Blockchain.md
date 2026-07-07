# `PWN::Blockchain` — BTC · ETH

Lightweight helpers for on-chain recon and wallet interaction.
Source: `lib/pwn/blockchain/*.rb`.

| Module | Purpose |
|---|---|
| `PWN::Blockchain::BTC` | Address balance/UTXO lookup, tx broadcast, key helpers |
| `PWN::Blockchain::ETH` | Address balance, contract call, event log query |

Also exposed to the agent via `PWN::AI::Agent::BTC` for wallet-aware prompts.

```ruby
PWN::Blockchain::BTC.balance(address: 'bc1q…')
PWN::Blockchain::ETH.call(contract: '0x…', method: 'owner()')
```

[← Home](Home.md)
