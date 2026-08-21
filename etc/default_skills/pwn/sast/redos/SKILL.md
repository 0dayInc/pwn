---
name: pwn-sast-redos
description: Drive PWN::SAST::ReDOS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::ReDOS
  source: pwn/sast/redos.rb
---

# PWN::SAST::ReDOS

SAST Module used to identify Regular Expression DOS within source code. For more information, see: https://www.owasp.org/index.php/Regular_expression_Denial_of_Service_-_ReDoS

## When to use

Call `PWN::SAST::ReDOS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/redos.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::ReDOS.help
PWN::SAST::ReDOS.scan(opts)
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

`pwn/sast/redos.rb`

## Verification

`PWN::SAST::ReDOS.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
