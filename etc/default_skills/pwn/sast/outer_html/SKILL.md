---
name: pwn-sast-outerhtml
description: Drive PWN::SAST::OuterHTML from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::OuterHTML
  source: pwn/sast/outer_html.rb
---

# PWN::SAST::OuterHTML

SAST Module used to identify any outerHTML function/method declarations within source code in an effort to determine if XSS is possible.

## When to use

Call `PWN::SAST::OuterHTML` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/outer_html.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::OuterHTML.help
PWN::SAST::OuterHTML.scan(opts)
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

`pwn/sast/outer_html.rb`

## Verification

`PWN::SAST::OuterHTML.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
