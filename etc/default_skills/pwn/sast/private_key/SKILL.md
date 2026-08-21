---
name: pwn-sast-privatekey
description: Drive PWN::SAST::PrivateKey from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::PrivateKey
  source: pwn/sast/private_key.rb
---

# PWN::SAST::PrivateKey

SAST Module used to identify private keys used for authenticating with remote hosts.

## When to use

Call `PWN::SAST::PrivateKey` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/private_key.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::PrivateKey.help
PWN::SAST::PrivateKey.scan(opts)
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

`pwn/sast/private_key.rb`

## Verification

`PWN::SAST::PrivateKey.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
