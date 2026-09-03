---
name: pwn-plugins-vault
description: Drive PWN::Plugins::Vault from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Vault
  source: pwn/plugins/vault.rb
---

# PWN::Plugins::Vault

Used to encrypt/decrypt configuration files leveraging AES256

## When to use

Call `PWN::Plugins::Vault` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/vault.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Vault.help
PWN::Plugins::Vault.refresh_encryption_secrets(opts)
```

## Public methods

- `refresh_encryption_secrets`
- `create`
- `decrypt`
- `dump`
- `edit`
- `encrypt`
- `file_encrypted`
- `store`
- `fetch`
- `expand`
- `redact`
- `authors`
- `help`
- `file_encrypted?`

## Source

`pwn/plugins/vault.rb`

## Verification

`PWN::Plugins::Vault.respond_to?(:refresh_encryption_secrets)` after the
module is loaded. Read the source for parameter names.
