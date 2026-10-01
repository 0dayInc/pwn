---
name: pwn-plugins-repl-aiconsoleusage
description: Drive PWN::Plugins::REPL::AIConsoleUsage from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::AIConsoleUsage
  source: pwn/plugins/repl/ai_console_usage.rb
---

# PWN::Plugins::REPL::AIConsoleUsage

Provider-reported token totals. USD comes from the active model's published prices, then from explicitly configured rates. Missing prices stay unavailable.

## When to use

Call `PWN::Plugins::REPL::AIConsoleUsage` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/ai_console_usage.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::AIConsoleUsage.help
PWN::Plugins::REPL::AIConsoleUsage.normalize(opts)
```

## Public methods

- `normalize`
- `estimate`
- `authors`
- `help`

## Source

`pwn/plugins/repl/ai_console_usage.rb`

## Verification

`PWN::Plugins::REPL::AIConsoleUsage.respond_to?(:normalize)` after the
module is loaded. Read the source for parameter names.
