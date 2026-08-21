---
name: pwn-sast-emoticon
description: Drive PWN::SAST::Emoticon from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Emoticon
  source: pwn/sast/emoticon.rb
---

# PWN::SAST::Emoticon

SAST Module used to identify portions of code marked by developers as interesting for whatever reason.

## When to use

Call `PWN::SAST::Emoticon` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/emoticon.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Emoticon.help
PWN::SAST::Emoticon.scan(opts)
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

`pwn/sast/emoticon.rb`

## Verification

`PWN::SAST::Emoticon.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
