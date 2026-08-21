---
name: pwn-sast-throwerrors
description: Drive PWN::SAST::ThrowErrors from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::ThrowErrors
  source: pwn/sast/throw_errors.rb
---

# PWN::SAST::ThrowErrors

SAST Module used to identify whether error messages are sanitized properly.

## When to use

Call `PWN::SAST::ThrowErrors` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/throw_errors.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::ThrowErrors.help
PWN::SAST::ThrowErrors.scan(opts)
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

`pwn/sast/throw_errors.rb`

## Verification

`PWN::SAST::ThrowErrors.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
