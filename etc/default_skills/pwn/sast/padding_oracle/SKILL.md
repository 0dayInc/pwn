---
name: pwn-sast-paddingoracle
description: Drive PWN::SAST::PaddingOracle from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::PaddingOracle
  source: pwn/sast/padding_oracle.rb
---

# PWN::SAST::PaddingOracle

SAST Module used to identify padding oracle vulnerabilities involving weak CBC block cipher padding.

## When to use

Call `PWN::SAST::PaddingOracle` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/padding_oracle.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::PaddingOracle.help
PWN::SAST::PaddingOracle.scan(opts)
```

## Public methods

- `scan`
- `security_references`
- `authors`
- `help`

## References

- `references/security.md` — CWE / NIST mapping

## Source

`pwn/sast/padding_oracle.rb`

## Verification

`PWN::SAST::PaddingOracle.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
