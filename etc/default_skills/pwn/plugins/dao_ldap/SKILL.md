---
name: pwn-plugins-daoldap
description: Drive PWN::Plugins::DAOLDAP from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::DAOLDAP
  source: pwn/plugins/dao_ldap.rb
---

# PWN::Plugins::DAOLDAP

This plugin is a data access object used for interacting w/ Active Directory/LDAP Servers

## When to use

Call `PWN::Plugins::DAOLDAP` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/dao_ldap.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::DAOLDAP.help
PWN::Plugins::DAOLDAP.connect(opts)
```

## Public methods

- `connect`
- `get_employee_by_username`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/dao_ldap.rb`

## Verification

`PWN::Plugins::DAOLDAP.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
