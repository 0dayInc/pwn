---
name: pwn-sast-localstorage
description: Drive PWN::SAST::LocalStorage from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::LocalStorage
  source: pwn/sast/local_storage.rb
---

# PWN::SAST::LocalStorage

SAST Module used to identify any localStorage function/method declarations within source code in an effort to determine if XSS is possible

## When to use

Call `PWN::SAST::LocalStorage` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/local_storage.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::LocalStorage.help
PWN::SAST::LocalStorage.scan(opts)
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

`pwn/sast/local_storage.rb`

## Verification

`PWN::SAST::LocalStorage.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
