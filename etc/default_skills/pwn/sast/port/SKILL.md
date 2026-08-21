---
name: pwn-sast-port
description: Drive PWN::SAST::Port from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Port
  source: pwn/sast/port.rb
---

# PWN::SAST::Port

SAST Module used to identify port declarations and network connections within source code to get a sense around appropriate secure network communications in place.

## When to use

Call `PWN::SAST::Port` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/port.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Port.help
PWN::SAST::Port.scan(opts)
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

`pwn/sast/port.rb`

## Verification

`PWN::SAST::Port.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
