---
name: pwn-ai-agent-burpsuite
description: Drive PWN::AI::Agent::BurpSuite from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::BurpSuite
  source: pwn/ai/agent/burp_suite.rb
---

# PWN::AI::Agent::BurpSuite

This module is an AI agent designed to analyze HTTP request/response pairs and WebSocket messages for high-impact vulnerabilities, with a focus on XSS and related issues. It provides detailed analysis and generates PoCs for identified vulnerabilities.

## When to use

Call `PWN::AI::Agent::BurpSuite` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/burp_suite.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::BurpSuite.help
PWN::AI::Agent::BurpSuite.analyze(opts)
```

## Public methods

- `analyze`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/agent/burp_suite.rb`

## Verification

`PWN::AI::Agent::BurpSuite.respond_to?(:analyze)` after the
module is loaded. Read the source for parameter names.
