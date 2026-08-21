---
name: pwn-plugins-log
description: Drive PWN::Plugins::Log from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Log
  source: pwn/plugins/log.rb
---

# PWN::Plugins::Log

This plugin is used to instantiate a PWN logger with a custom message format

## When to use

Call `PWN::Plugins::Log` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/log.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Log.help
PWN::Plugins::Log.append(opts)
```

## Public methods

- `append`
- `debug_enabled`
- `debug_log_path`
- `start_debug`
- `next_request_log`
- `finish_request_log`
- `stop_debug`
- `capture_stderr`
- `spinner_frame`
- `raw_stderr`
- `quiet_tui`
- `loud_tui`
- `progress`
- `note_interrupt`
- `note_exception`
- `mirror_tui`
- `start_trace`
- `stop_trace`
- `authors`
- `help`

## Source

`pwn/plugins/log.rb`

## Verification

`PWN::Plugins::Log.respond_to?(:append)` after the
module is loaded. Read the source for parameter names.
