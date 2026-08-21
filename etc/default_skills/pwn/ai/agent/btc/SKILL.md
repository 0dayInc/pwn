---
name: pwn-ai-agent-btc
description: Drive PWN::AI::Agent::BTC from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::BTC
  source: pwn/ai/agent/btc.rb
---

# PWN::AI::Agent::BTC

This module is an AI agent designed to analyze Bitcoin blockchain information. It provides insights and summaries based on the latest block data retrieved from a Bitcoin node using `PWN::Blockchain::BTC.get_latest_block`.

## When to use

Call `PWN::AI::Agent::BTC` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/btc.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::BTC.help
PWN::AI::Agent::BTC.analyze(opts)
```

## Public methods

- `analyze`
- `authors`
- `help`

## Source

`pwn/ai/agent/btc.rb`

## Verification

`PWN::AI::Agent::BTC.respond_to?(:analyze)` after the
module is loaded. Read the source for parameter names.
