---
name: pwn-ai-agent-assembly
description: Drive PWN::AI::Agent::Assembly from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Assembly
  source: pwn/ai/agent/assembly.rb
---

# PWN::AI::Agent::Assembly

This module is an AI agent designed to analyze assembly code, including both opcodes and instructions, for various architectures and endianness. It provides insights into the functionality of the assembly code and can also convert it to C/C++ code when possible.

## When to use

Call `PWN::AI::Agent::Assembly` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/assembly.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Assembly.help
PWN::AI::Agent::Assembly.analyze(opts)
```

## Public methods

- `analyze`
- `authors`
- `help`

## Source

`pwn/ai/agent/assembly.rb`

## Verification

`PWN::AI::Agent::Assembly.respond_to?(:analyze)` after the
module is loaded. Read the source for parameter names.
