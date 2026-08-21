---
name: pwn-reports-phone
description: Drive PWN::Reports::Phone from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::Phone
  source: pwn/reports/phone.rb
---

# PWN::Reports::Phone

This plugin generates the War Dialing results produced by pwn_phone.

## When to use

Call `PWN::Reports::Phone` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/phone.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::Phone.help
PWN::Reports::Phone.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/reports/phone.rb`

## Verification

`PWN::Reports::Phone.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
