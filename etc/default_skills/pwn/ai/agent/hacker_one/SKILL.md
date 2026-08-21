---
name: pwn-ai-agent-hackerone
description: Drive PWN::AI::Agent::HackerOne from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::HackerOne
  source: pwn/ai/agent/hacker_one.rb
---

# PWN::AI::Agent::HackerOne

This module is an AI agent designed to analyze various aspects of HackerOne bug bounty programs, including bounty program details, scope details, and hacktivity details. It provides insights and recommendations based on the provided data to help security researchers optimize their efforts on the platform.

## When to use

Call `PWN::AI::Agent::HackerOne` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/hacker_one.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::HackerOne.help
PWN::AI::Agent::HackerOne.analyze(opts)
```

## Public methods

- `analyze`
- `authors`
- `help`

## Source

`pwn/ai/agent/hacker_one.rb`

## Verification

`PWN::AI::Agent::HackerOne.respond_to?(:analyze)` after the
module is loaded. Read the source for parameter names.
