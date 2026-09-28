---
name: pwn-plugins-repl-aiconsole
description: Drive PWN::Plugins::REPL::AIConsole from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::AIConsole
  source: pwn/plugins/repl/ai_console.rb
---

# PWN::Plugins::REPL::AIConsole

Single-owner fullscreen agent console. Workers never paint the terminal.

## When to use

Call `PWN::Plugins::REPL::AIConsole` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/ai_console.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::AIConsole.help
PWN::Plugins::REPL::AIConsole.run(opts)
```

## Public methods

- `run`
- `theme`
- `authors`
- `help`

## Source

`pwn/plugins/repl/ai_console.rb`

## Verification

`PWN::Plugins::REPL::AIConsole.respond_to?(:run)` after the
module is loaded. Read the source for parameter names.
