---
name: pwn-sast-token
description: Drive PWN::SAST::Token from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Token
  source: pwn/sast/token.rb
---

# PWN::SAST::Token

SAST Module used to identify any reference within source code of authorization tokens.

## When to use

Call `PWN::SAST::Token` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/token.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Token.help
PWN::SAST::Token.scan(opts)
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

`pwn/sast/token.rb`

## Verification

`PWN::SAST::Token.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
