---
name: pwn-sast-eval
description: Drive PWN::SAST::Eval from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::Eval
  source: pwn/sast/eval.rb
---

# PWN::SAST::Eval

SAST Module used to identify any eval function/method declarations within source code in an effort to determine if arbitrary command/code execution is possible

## When to use

Call `PWN::SAST::Eval` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/eval.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::Eval.help
PWN::SAST::Eval.scan(opts)
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

`pwn/sast/eval.rb`

## Verification

`PWN::SAST::Eval.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
