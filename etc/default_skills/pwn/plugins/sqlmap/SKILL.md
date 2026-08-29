---
name: pwn-plugins-sqlmap
description: Drive PWN::Plugins::Sqlmap from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Sqlmap
  source: pwn/plugins/sqlmap.rb
---

# PWN::Plugins::Sqlmap

sqlmap wrapper to pair with SAST SQL detection.

## When to use

Call `PWN::Plugins::Sqlmap` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/sqlmap.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Sqlmap.help
PWN::Plugins::Sqlmap.required_bins(opts)
```

## Public methods

- `required_bins`
- `run`
- `authors`
- `help`

## Source

`pwn/plugins/sqlmap.rb`

## Verification

`PWN::Plugins::Sqlmap.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
