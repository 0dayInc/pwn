---
name: pwn-plugins-pwnlogger
description: Drive PWN::Plugins::PWNLogger from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::PWNLogger
  source: pwn/plugins/pwn_logger.rb
---

# PWN::Plugins::PWNLogger

This plugin is used to instantiate a PWN logger with a custom message format

## When to use

Call `PWN::Plugins::PWNLogger` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/pwn_logger.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::PWNLogger.help
PWN::Plugins::PWNLogger.create(opts)
```

## Public methods

- `create`
- `authors`
- `help`

## Source

`pwn/plugins/pwn_logger.rb`

## Verification

`PWN::Plugins::PWNLogger.respond_to?(:create)` after the
module is loaded. Read the source for parameter names.
