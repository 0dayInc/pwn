---
name: pwn-sast-sudo
description: Drive PWN::SAST::Sudo from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Sudo
  source: pwn/sast/sudo.rb
---

# PWN::SAST::Sudo

SAST Module used to identify if cmd execution and/or privilege escalation is possible.

## When to use

Call `PWN::SAST::Sudo` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/sudo.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Sudo.help
PWN::SAST::Sudo.scan(opts)
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

`pwn/sast/sudo.rb`

## Verification

`PWN::SAST::Sudo.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
