---
name: pwn-sast-shell
description: Drive PWN::SAST::Shell from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Shell
  source: pwn/sast/shell.rb
---

# PWN::SAST::Shell

SAST Module used to identify if application is shelling-out which may lead to arbitrary command execution

## When to use

Call `PWN::SAST::Shell` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/shell.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Shell.help
PWN::SAST::Shell.scan(opts)
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

`pwn/sast/shell.rb`

## Verification

`PWN::SAST::Shell.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
