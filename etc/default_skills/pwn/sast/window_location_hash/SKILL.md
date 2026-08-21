---
name: pwn-sast-windowlocationhash
description: Drive PWN::SAST::WindowLocationHash from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::WindowLocationHash
  source: pwn/sast/window_location_hash.rb
---

# PWN::SAST::WindowLocationHash

SAST Module used to identify the potential for DOM-based XSS in the application.

## When to use

Call `PWN::SAST::WindowLocationHash` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/window_location_hash.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::WindowLocationHash.help
PWN::SAST::WindowLocationHash.scan(opts)
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

`pwn/sast/window_location_hash.rb`

## Verification

`PWN::SAST::WindowLocationHash.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
