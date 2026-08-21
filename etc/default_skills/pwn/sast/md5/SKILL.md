---
name: pwn-sast-md5
description: Drive PWN::SAST::MD5 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::MD5
  source: pwn/sast/md5.rb
---

# PWN::SAST::MD5

SAST Module used to identify MD5 hash related objects, methods, classes, etc. to determine if deprecated hashing is still supported.

## When to use

Call `PWN::SAST::MD5` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/md5.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::MD5.help
PWN::SAST::MD5.scan(opts)
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

`pwn/sast/md5.rb`

## Verification

`PWN::SAST::MD5.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
