---
name: pwn-sast-innerhtml
description: Drive PWN::SAST::InnerHTML from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::InnerHTML
  source: pwn/sast/inner_html.rb
---

# PWN::SAST::InnerHTML

SAST Module used to identify any innerHTML function/method declarations within source code in an effort to determine if XSS is possible

## When to use

Call `PWN::SAST::InnerHTML` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/inner_html.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::InnerHTML.help
PWN::SAST::InnerHTML.scan(opts)
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

`pwn/sast/inner_html.rb`

## Verification

`PWN::SAST::InnerHTML.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
