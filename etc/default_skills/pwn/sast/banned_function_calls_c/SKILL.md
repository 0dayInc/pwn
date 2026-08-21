---
name: pwn-sast-bannedfunctioncallsc
description: Drive PWN::SAST::BannedFunctionCallsC from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST::BannedFunctionCallsC
  source: pwn/sast/banned_function_calls_c.rb
---

# PWN::SAST::BannedFunctionCallsC

SAST Module used to identify banned function calls in C & C++ code per: https://msdn.microsoft.com/en-us/library/bb288454.aspx

## When to use

Call `PWN::SAST::BannedFunctionCallsC` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast/banned_function_calls_c.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST::BannedFunctionCallsC.help
PWN::SAST::BannedFunctionCallsC.scan(opts)
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

`pwn/sast/banned_function_calls_c.rb`

## Verification

`PWN::SAST::BannedFunctionCallsC.respond_to?(:scan)` after the
module is loaded. Read the source for parameter names.
