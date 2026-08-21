---
name: pwn-sast-signature
description: Drive PWN::SAST::Signature from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Signature
  source: pwn/sast/signature.rb
---

# PWN::SAST::Signature

SAST Module used to identify private keys used for authenticating with remote hosts.

## When to use

Call `PWN::SAST::Signature` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/signature.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Signature.help
PWN::SAST::Signature.scan(opts)
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

`pwn/sast/signature.rb`

## Verification

`PWN::SAST::Signature.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
