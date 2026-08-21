---
name: pwn-sdr
description: Drive PWN::SDR from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR
  source: pwn/sdr.rb
---

# PWN::SDR

This file, using the autoload directive loads SDR modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::SDR` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR.help
PWN::SDR.hz_to_s(opts)
```

## Public methods

- `hz_to_s`
- `hz_to_i`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sdr.rb`

## Verification

`PWN::SDR.respond_to?(:hz_to_s)` after the
module is loaded. Read the source for parameter names.
