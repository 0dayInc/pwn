---
name: pwn-plugins-repl-irc
description: Drive PWN::Plugins::REPL::IRC from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::IRC
  source: pwn/plugins/repl/irc.rb
---

# PWN::Plugins::REPL::IRC

pwn-irc REPL mode.

## When to use

Call `PWN::Plugins::REPL::IRC` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/irc.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::IRC.help
PWN::Plugins::REPL::IRC.add_commands(opts)
```

## Public methods

- `add_commands`
- `authors`
- `help`

## Source

`pwn/plugins/repl/irc.rb`

## Verification

`PWN::Plugins::REPL::IRC.respond_to?(:add_commands)` after the
module is loaded. Read the source for parameter names.
