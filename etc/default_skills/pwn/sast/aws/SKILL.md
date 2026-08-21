---
name: pwn-sast-aws
description: Drive PWN::SAST::AWS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::AWS
  source: pwn/sast/aws.rb
---

# PWN::SAST::AWS

SAST Module used to identify sensitive AWS AuthN artifacts.

## When to use

Call `PWN::SAST::AWS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/aws.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::AWS.help
PWN::SAST::AWS.scan(opts)
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

`pwn/sast/aws.rb`

## Verification

`PWN::SAST::AWS.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
