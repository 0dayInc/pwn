---
name: pwn-sast-base64
description: Drive PWN::SAST::Base64 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Base64
  source: pwn/sast/base64.rb
---

# PWN::SAST::Base64

SAST Module used to identify Base64 encoded strings that may have sensitive artifacts when decoded.

## When to use

Call `PWN::SAST::Base64` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/base64.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Base64.help
PWN::SAST::Base64.scan(opts)
```

## Public methods

- `scan`
- `security_references`
- `authors`
- `help`

## References

- `references/security.md` — CWE / NIST mapping

## Source

`pwn/sast/base64.rb`

## Verification

`PWN::SAST::Base64.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
