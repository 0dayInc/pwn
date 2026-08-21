---
name: pwn-sast-keystore
description: Drive PWN::SAST::Keystore from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Keystore
  source: pwn/sast/keystore.rb
---

# PWN::SAST::Keystore

SAST Module used to identify weak passwords/configurations around key stores.

## When to use

Call `PWN::SAST::Keystore` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/keystore.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Keystore.help
PWN::SAST::Keystore.scan(opts)
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

`pwn/sast/keystore.rb`

## Verification

`PWN::SAST::Keystore.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
