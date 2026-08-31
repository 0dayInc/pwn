---
name: pwn-plugins-credentialattack
description: Drive PWN::Plugins::CredentialAttack from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::CredentialAttack
  source: pwn/plugins/credential_attack.rb
---

# PWN::Plugins::CredentialAttack

hydra/john/hashcat wrappers and ~/.pwn/wordlists convention.

## When to use

Call `PWN::Plugins::CredentialAttack` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/credential_attack.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::CredentialAttack.help
PWN::Plugins::CredentialAttack.required_bins(opts)
```

## Public methods

- `required_bins`
- `wordlist_dir`
- `hydra`
- `john`
- `hashcat`
- `medusa`
- `identify_hash`
- `fetch_seclists`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/credential_attack.rb`

## Verification

`PWN::Plugins::CredentialAttack.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
