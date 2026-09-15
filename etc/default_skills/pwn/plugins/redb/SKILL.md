---
name: pwn-plugins-redb
description: Drive PWN::Plugins::REDB from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REDB
  source: pwn/plugins/redb.rb
---

# PWN::Plugins::REDB

Persistent per-binary analysis DB under ~/.pwn/redb.

## When to use

Call `PWN::Plugins::REDB` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/redb.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REDB.help
PWN::Plugins::REDB.open(opts)
```

## Public methods

- `open`
- `funcs`
- `xrefs_to`
- `strings`
- `decompile`
- `annotate`
- `authors`
- `help`

## Source

`pwn/plugins/redb.rb`

## Verification

`PWN::Plugins::REDB.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
