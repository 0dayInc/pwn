---
name: pwn-plugins-repl
description: Drive PWN::Plugins::REPL from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL
  source: pwn/plugins/repl.rb
---

# PWN::Plugins::REPL

This module contains methods related to the pwn REPL Driver.

## When to use

Call `PWN::Plugins::REPL` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL.help
PWN::Plugins::REPL.ready_tty(opts)
```

## Public methods

- `ready_tty`
- `compact_context_tokens`
- `refresh_ps1_proc`
- `add_commands`
- `add_hooks`
- `pwn_ai_complete_kind`
- `pwn_ai_complete`
- `pwn_ai_complete_command`
- `pwn_ai_complete_path`
- `pwn_ai_complete_ruby`
- `install_pwn_ai_completer`
- `restore_pwn_ai_completer`
- `pwn_ai_dispatch_slash`
- `pwn_ai_run_cron`
- `pwn_ai_run_sessions`
- `pwn_ai_run_memory`
- `pwn_ai_run_skills`
- `enable_autocomplete`
- `start`
- `authors`
- `help`

## Source

`pwn/plugins/repl.rb`

## Verification

`PWN::Plugins::REPL.respond_to?(:ready_tty)` after the
module is loaded. Read the source for parameter names.
