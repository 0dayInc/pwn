---
name: pwn-ai-agent-gqrx
description: Drive PWN::AI::Agent::GQRX from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::GQRX
  source: pwn/ai/agent/gqrx.rb
---

# PWN::AI::Agent::GQRX

This module is an AI agent designed to analyze signal data captured by a software-defined-radio using GQRX. It uses the PWN::AI::Agent::Reflect.on method to analyze the signal data and provide insights based on the location where the data was captured. The agent can determine if the frequency is licensed or unlicensed based on FCC records and provide relevant information about the transmission. This module is useful for security professionals, researchers, and hobbyists interested in analyzing radio signals and understanding their context.

## When to use

Call `PWN::AI::Agent::GQRX` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/gqrx.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::GQRX.help
PWN::AI::Agent::GQRX.analyze(opts)
```

## Public methods

- `analyze`
- `authors`
- `help`

## Source

`pwn/ai/agent/gqrx.rb`

## Verification

`PWN::AI::Agent::GQRX.respond_to?(:analyze)` after the
module is loaded. Read the source for parameter names.
