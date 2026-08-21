---
name: pwn-sast-postmessage
description: Drive PWN::SAST::PostMessage from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::PostMessage
  source: pwn/sast/post_message.rb
---

# PWN::SAST::PostMessage

SAST Module used to identify any postMessage function/method declarations within source code in an effort to determine if XSS is possible

## When to use

Call `PWN::SAST::PostMessage` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/post_message.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::PostMessage.help
PWN::SAST::PostMessage.scan(opts)
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

`pwn/sast/post_message.rb`

## Verification

`PWN::SAST::PostMessage.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
