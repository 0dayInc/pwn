---
name: pwn-plugins-daopostgres
description: Drive PWN::Plugins::DAOPostgres from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::DAOPostgres
  source: pwn/plugins/dao_postgres.rb
---

# PWN::Plugins::DAOPostgres

This plugin is a data access object used for interacting w/ PostgreSQL databases.

## When to use

Call `PWN::Plugins::DAOPostgres` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/dao_postgres.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::DAOPostgres.help
PWN::Plugins::DAOPostgres.connect(opts)
```

## Public methods

- `connect`
- `sql_statement`
- `list_all_columns_by_table`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/dao_postgres.rb`

## Verification

`PWN::Plugins::DAOPostgres.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
