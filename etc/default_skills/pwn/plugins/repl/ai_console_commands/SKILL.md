---
name: pwn-plugins-repl-aiconsolecommands
description: Drive PWN::Plugins::REPL::AIConsoleCommands from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::AIConsoleCommands
  source: pwn/plugins/repl/ai_console_commands.rb
---

# PWN::Plugins::REPL::AIConsoleCommands

Live slash-command parameter completion. Never calls a provider.

## When to use

Call `PWN::Plugins::REPL::AIConsoleCommands` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/ai_console_commands.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::AIConsoleCommands.help
PWN::Plugins::REPL::AIConsoleCommands.complete(opts)
```

## Public methods

- `complete`
- `authors`
- `help`

## Source

`pwn/plugins/repl/ai_console_commands.rb`

## Verification

`PWN::Plugins::REPL::AIConsoleCommands.respond_to?(:complete)` after the
module is loaded. Read the source for parameter names.
