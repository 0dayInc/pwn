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
- `leave_special_mode`
- `enable_autocomplete`
- `start`
- `authors`
- `help`
- `install_pwn_ai_completer!`
- `install_pwn_mesh_completer!`
- `leave_special_mode!`
- `mesh_menu_pick`
- `mesh_reset_input!`
- `persist_ai_selection`
- `persist_mesh_env`
- `pwn_ai_activation_session`
- `pwn_ai_complete`
- `pwn_ai_complete_command`
- `pwn_ai_complete_kind`
- `pwn_ai_complete_path`
- `pwn_ai_complete_ruby`
- `pwn_ai_dispatch_slash!`
- `pwn_ai_engine_model`
- `pwn_ai_engines`
- `pwn_ai_list_llms`
- `pwn_ai_memory_command`
- `pwn_ai_model_ids`
- `pwn_ai_profile_command`
- `pwn_ai_provider_class`
- `pwn_ai_run_cron`
- `pwn_ai_run_learning`
- `pwn_ai_run_mcp`
- `pwn_ai_run_memory`
- `pwn_ai_run_model`
- `pwn_ai_run_sessions`
- `pwn_ai_run_skills`
- `pwn_mesh_complete`
- `pwn_mesh_dispatch_slash!`
- `pwn_mesh_menu_rows`
- `ready_tty!`
- `restore_pwn_ai_completer!`

## Source

`pwn/plugins/repl.rb`

## Verification

`PWN::Plugins::REPL.respond_to?(:ready_tty)` after the
module is loaded. Read the source for parameter names.
