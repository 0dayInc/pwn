---
name: pwn-sast-version
description: Drive PWN::SAST::Version from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Version
  source: pwn/sast/version.rb
---

# PWN::SAST::Version

SAST Module used to detect version information within all files in a source repo

## When to use

Call `PWN::SAST::Version` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/version.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Version.help
PWN::SAST::Version.scan(opts)
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

`pwn/sast/version.rb`

## Verification

`PWN::SAST::Version.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
