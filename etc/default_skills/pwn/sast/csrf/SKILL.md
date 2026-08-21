---
name: pwn-sast-csrf
description: Drive PWN::SAST::CSRF from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::CSRF
  source: pwn/sast/csrf.rb
---

# PWN::SAST::CSRF

SAST Module used to identify indicators of improper CSRF protection. If nothing appears in the report, this may be an indicator of NO CSRF protection.

## When to use

Call `PWN::SAST::CSRF` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/csrf.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::CSRF.help
PWN::SAST::CSRF.scan(opts)
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

`pwn/sast/csrf.rb`

## Verification

`PWN::SAST::CSRF.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
