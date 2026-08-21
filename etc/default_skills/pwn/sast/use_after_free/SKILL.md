---
name: pwn-sast-useafterfree
description: Drive PWN::SAST::UseAfterFree from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::UseAfterFree
  source: pwn/sast/use_after_free.rb
---

# PWN::SAST::UseAfterFree

SAST Module used to identify banned function calls in C & C++ code per: https://msdn.microsoft.com/en-us/library/bb288454.aspx

## When to use

Call `PWN::SAST::UseAfterFree` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/use_after_free.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::UseAfterFree.help
PWN::SAST::UseAfterFree.scan(opts)
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

`pwn/sast/use_after_free.rb`

## Verification

`PWN::SAST::UseAfterFree.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
