---
name: pwn-backups
description: Drive PWN::Backups from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Backups
  source: pwn/backups.rb
---

# PWN::Backups

All first-party recovery copies share one serialized seven-generation store. Evidence artifacts are not recovery copies and must not enter this store.

## When to use

Call `PWN::Backups` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/backups.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Backups.help
PWN::Backups.active(opts)
```

## Public methods

- `active`
- `transaction`
- `directory`
- `capture`
- `configure`
- `reconcile`
- `relocate_legacy`
- `authors`
- `help`
- `active?`

## Source

`pwn/backups.rb`

## Verification

`PWN::Backups.respond_to?(:active)` after the
module is loaded. Read the source for parameter names.
