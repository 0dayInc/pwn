---
name: pwn-ai-agent-sast
description: Drive PWN::AI::Agent::SAST from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::SAST
  source: pwn/ai/agent/sast.rb
---

# PWN::AI::Agent::SAST

This module is an AI agent designed to analyze SAST antipatterns within source code repositories. It identifies common coding mistakes, security vulnerabilities, and areas for improvement in code quality. The agent generates an EPSS score for each identified issue, indicating the likelihood of exploitation. It provides detailed explanations of the issues found, along with recommendations for remediation and best practices to enhance code security and maintainability.

## When to use

Call `PWN::AI::Agent::SAST` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/sast.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::SAST.help
PWN::AI::Agent::SAST.analyze(opts)
```

## Public methods

- `analyze`
- `authors`
- `help`

## Source

`pwn/ai/agent/sast.rb`

## Verification

`PWN::AI::Agent::SAST.respond_to?(:analyze)` after the
module is loaded. Read the source for parameter names.
