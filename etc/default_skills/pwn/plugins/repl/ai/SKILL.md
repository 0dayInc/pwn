---
name: pwn-plugins-repl-ai
description: Drive PWN::Plugins::REPL::AI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::AI
  source: pwn/plugins/repl/ai.rb
---

# PWN::Plugins::REPL::AI

pwn-ai REPL mode.

## When to use

Call `PWN::Plugins::REPL::AI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/ai.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::AI.help
PWN::Plugins::REPL::AI.add_commands(opts)
```

## Public methods

- `add_commands`
- `authors`
- `help`

## Source

`pwn/plugins/repl/ai.rb`

## Verification

`PWN::Plugins::REPL::AI.respond_to?(:add_commands)` after the
module is loaded. Read the source for parameter names.
