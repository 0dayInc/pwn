---
name: pwn-sast-locationhash
description: Drive PWN::SAST::LocationHash from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::LocationHash
  source: pwn/sast/location_hash.rb
---

# PWN::SAST::LocationHash

SAST Module used to identify any location.hash function/method declarations within source code in an effort to determine if XSS is possible

## When to use

Call `PWN::SAST::LocationHash` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/location_hash.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::LocationHash.help
PWN::SAST::LocationHash.scan(opts)
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

`pwn/sast/location_hash.rb`

## Verification

`PWN::SAST::LocationHash.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
