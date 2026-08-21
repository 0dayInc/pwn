---
name: pwn-plugins-daosqlite3
description: Drive PWN::Plugins::DAOSQLite3 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::DAOSQLite3
  source: pwn/plugins/dao_sqlite3.rb
---

# PWN::Plugins::DAOSQLite3

This plugin is a data access object used for interacting w/ SQLite3 databases.

## When to use

Call `PWN::Plugins::DAOSQLite3` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/dao_sqlite3.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::DAOSQLite3.help
PWN::Plugins::DAOSQLite3.connect(opts)
```

## Public methods

- `connect`
- `sql_statement`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/dao_sqlite3.rb`

## Verification

`PWN::Plugins::DAOSQLite3.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
