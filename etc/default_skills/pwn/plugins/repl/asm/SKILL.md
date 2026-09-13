---
name: pwn-plugins-repl-asm
description: Drive PWN::Plugins::REPL::ASM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::ASM
  source: pwn/plugins/repl/asm.rb
---

# PWN::Plugins::REPL::ASM

pwn-asm REPL mode.

## When to use

Call `PWN::Plugins::REPL::ASM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/asm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::ASM.help
PWN::Plugins::REPL::ASM.add_commands(opts)
```

## Public methods

- `add_commands`
- `authors`
- `help`

## Source

`pwn/plugins/repl/asm.rb`

## Verification

`PWN::Plugins::REPL::ASM.respond_to?(:add_commands)` after the
module is loaded. Read the source for parameter names.
