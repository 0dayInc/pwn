---
name: pwn-sast-password
description: Drive PWN::SAST::Password from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Password
  source: pwn/sast/password.rb
---

# PWN::SAST::Password

SAST Module used to identify hard-code/plain-text passwords within source code.

## When to use

Call `PWN::SAST::Password` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/password.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Password.help
PWN::SAST::Password.scan(opts)
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

`pwn/sast/password.rb`

## Verification

`PWN::SAST::Password.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
