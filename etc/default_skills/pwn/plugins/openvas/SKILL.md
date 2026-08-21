---
name: pwn-plugins-openvas
description: Drive PWN::Plugins::OpenVAS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::OpenVAS
  source: pwn/plugins/openvas.rb
---

# PWN::Plugins::OpenVAS

This plugin is used for interacting w/ OpenVAS using OMP (OpenVAS Management Protocol).

## When to use

Call `PWN::Plugins::OpenVAS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/openvas.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::OpenVAS.help
PWN::Plugins::OpenVAS.get_task_id(opts)
```

## Public methods

- `get_task_id`
- `start_task`
- `get_task_status`
- `last_report_id`
- `save_report`
- `get_report_types`
- `authors`
- `help`

## Source

`pwn/plugins/openvas.rb`

## Verification

`PWN::Plugins::OpenVAS.respond_to?(:get_task_id)` after the
module is loaded. Read the source for parameter names.
