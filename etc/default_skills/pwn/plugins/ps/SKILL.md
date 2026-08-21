---
name: pwn-plugins-ps
description: Drive PWN::Plugins::PS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::PS
  source: pwn/plugins/ps.rb
---

# PWN::Plugins::PS

This plugin is a simple wrapper around the ps command.

## When to use

Call `PWN::Plugins::PS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/ps.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::PS.help
PWN::Plugins::PS.list(opts)
```

## Public methods

- `list`
- `cleanup_pids`
- `authors`
- `help`

## Source

`pwn/plugins/ps.rb`

## Verification

`PWN::Plugins::PS.respond_to?(:list)` after the
module is loaded. Read the source for parameter names.
