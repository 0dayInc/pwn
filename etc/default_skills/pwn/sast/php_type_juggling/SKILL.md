---
name: pwn-sast-phptypejuggling
description: Drive PWN::SAST::PHPTypeJuggling from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::PHPTypeJuggling
  source: pwn/sast/php_type_juggling.rb
---

# PWN::SAST::PHPTypeJuggling

SAST Module used to identify loose comparisons (i.e. == instead of ===) within PHP source code.

## When to use

Call `PWN::SAST::PHPTypeJuggling` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/php_type_juggling.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::PHPTypeJuggling.help
PWN::SAST::PHPTypeJuggling.scan(opts)
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

`pwn/sast/php_type_juggling.rb`

## Verification

`PWN::SAST::PHPTypeJuggling.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
