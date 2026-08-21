---
name: pwn-plugins-msr206
description: Drive PWN::Plugins::MSR206 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::MSR206
  source: pwn/plugins/msr206.rb
---

# PWN::Plugins::MSR206

This plugin is used for interacting with a three track MSR206 Magnetic Stripe Reader / Writer

## When to use

Call `PWN::Plugins::MSR206` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/msr206.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::MSR206.help
PWN::Plugins::MSR206.connect(opts)
```

## Public methods

- `connect`
- `list_cmds`
- `set_protocol`
- `exec`
- `read_card`
- `backup_card`
- `write_card`
- `clone_card`
- `load_card_from_file`
- `update_card`
- `get_config`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/msr206.rb`

## Verification

`PWN::Plugins::MSR206.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
