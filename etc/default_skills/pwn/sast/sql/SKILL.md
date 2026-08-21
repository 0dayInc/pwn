---
name: pwn-sast-sql
description: Drive PWN::SAST::SQL from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::SQL
  source: pwn/sast/sql.rb
---

# PWN::SAST::SQL

SAST Module used to identify any reference within source code that may contain SQL to determine if SQL injeciton is possible.

## When to use

Call `PWN::SAST::SQL` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/sql.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::SQL.help
PWN::SAST::SQL.scan(opts)
```

## Public methods

- `scan`
- `security_references`
- `authors`
- `help`

## References

- `references/security.md` — CWE / NIST mapping
- `references/urls.md` — URLs from source

## Source

`pwn/sast/sql.rb`

## Verification

`PWN::SAST::SQL.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
