---
name: pwn-plugins-repl-vault
description: Drive PWN::Plugins::REPL::Vault from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::Vault
  source: pwn/plugins/repl/vault.rb
---

# PWN::Plugins::REPL::Vault

pwn-vault REPL mode.

## When to use

Call `PWN::Plugins::REPL::Vault` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/vault.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::Vault.help
PWN::Plugins::REPL::Vault.add_commands(opts)
```

## Public methods

- `add_commands`
- `authors`
- `help`

## Source

`pwn/plugins/repl/vault.rb`

## Verification

`PWN::Plugins::REPL::Vault.respond_to?(:add_commands)` after the
module is loaded. Read the source for parameter names.
