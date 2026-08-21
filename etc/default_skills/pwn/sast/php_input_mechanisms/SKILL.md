---
name: pwn-sast-phpinputmechanisms
description: Drive PWN::SAST::PHPInputMechanisms from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::PHPInputMechanisms
  source: pwn/sast/php_input_mechanisms.rb
---

# PWN::SAST::PHPInputMechanisms

SAST Module used to identify HTTP input mechanisms that exist in PHP code (e.g. $_REQUEST, $_GET, etc.)

## When to use

Call `PWN::SAST::PHPInputMechanisms` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/php_input_mechanisms.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::PHPInputMechanisms.help
PWN::SAST::PHPInputMechanisms.scan(opts)
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

`pwn/sast/php_input_mechanisms.rb`

## Verification

`PWN::SAST::PHPInputMechanisms.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
