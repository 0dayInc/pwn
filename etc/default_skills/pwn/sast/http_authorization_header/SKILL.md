---
name: pwn-sast-httpauthorizationheader
description: Drive PWN::SAST::HTTPAuthorizationHeader from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::HTTPAuthorizationHeader
  source: pwn/sast/http_authorization_header.rb
---

# PWN::SAST::HTTPAuthorizationHeader

SAST Module used to identify hard-code/plain-text passwords within source code.

## When to use

Call `PWN::SAST::HTTPAuthorizationHeader` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/http_authorization_header.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::HTTPAuthorizationHeader.help
PWN::SAST::HTTPAuthorizationHeader.scan(opts)
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

`pwn/sast/http_authorization_header.rb`

## Verification

`PWN::SAST::HTTPAuthorizationHeader.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
