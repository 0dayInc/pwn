---
name: pwn-sast-logger
description: Drive PWN::SAST::Logger from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Logger
  source: pwn/sast/logger.rb
---

# PWN::SAST::Logger

SAST Module used to identify whether sensitive artifacts such as passwords, pre-auth tokens, etc are persisted to log files (which may lead to unauthorized access).

## When to use

Call `PWN::SAST::Logger` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/logger.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Logger.help
PWN::SAST::Logger.scan(opts)
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

`pwn/sast/logger.rb`

## Verification

`PWN::SAST::Logger.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
