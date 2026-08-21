---
name: pwn-sast-ssl
description: Drive PWN::SAST::SSL from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::SSL
  source: pwn/sast/ssl.rb
---

# PWN::SAST::SSL

SAST Module used to identify any SSL/TLS reference within source code.

## When to use

Call `PWN::SAST::SSL` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/ssl.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::SSL.help
PWN::SAST::SSL.scan(opts)
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

`pwn/sast/ssl.rb`

## Verification

`PWN::SAST::SSL.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
