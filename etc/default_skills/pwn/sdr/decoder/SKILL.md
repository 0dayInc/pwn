---
name: pwn-sdr-decoder
description: Drive PWN::SDR::Decoder from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder
  source: pwn/sdr/decoder.rb
---

# PWN::SDR::Decoder

This file, using the autoload directive loads SDR modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::SDR::Decoder` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder.help
PWN::SDR::Decoder.resolve(opts)
```

## Public methods

- `resolve`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sdr/decoder.rb`

## Verification

`PWN::SDR::Decoder.respond_to?(:resolve)` after the
module is loaded. Read the source for parameter names.
