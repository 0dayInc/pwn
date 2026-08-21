---
name: pwn-sast-redirect
description: Drive PWN::SAST::Redirect from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Redirect
  source: pwn/sast/redirect.rb
---

# PWN::SAST::Redirect

SAST Module used to identify if applications allow arbritrary redirects to third-party URLs w/o a whitelist

## When to use

Call `PWN::SAST::Redirect` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/redirect.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Redirect.help
PWN::SAST::Redirect.scan(opts)
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

`pwn/sast/redirect.rb`

## Verification

`PWN::SAST::Redirect.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
