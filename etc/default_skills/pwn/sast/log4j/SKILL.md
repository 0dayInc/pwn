---
name: pwn-sast-log4j
description: Drive PWN::SAST::Log4J from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Log4J
  source: pwn/sast/log4j.rb
---

# PWN::SAST::Log4J

SAST Module used to identify command execution residing within Java source code.

## When to use

Call `PWN::SAST::Log4J` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/log4j.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Log4J.help
PWN::SAST::Log4J.scan(opts)
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

`pwn/sast/log4j.rb`

## Verification

`PWN::SAST::Log4J.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
