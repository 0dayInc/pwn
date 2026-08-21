---
name: pwn-sdr-decoder-rtl433
description: Drive PWN::SDR::Decoder::RTL433 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::RTL433
  source: pwn/sdr/decoder/rtl433.rb
---

# PWN::SDR::Decoder::RTL433

True-air + detector-fallback decoder for RTL433. Prefers PWN::FFI I/Q (RTL-SDR / ADALM-Pluto / HackRF / capture file) via Base.run_iq; degrades to Base.run_detector with no hardware.

## When to use

Call `PWN::SDR::Decoder::RTL433` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/rtl433.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::RTL433.help
PWN::SDR::Decoder::RTL433.decode(opts)
```

## Public methods

- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/rtl433.rb`

## Verification

`PWN::SDR::Decoder::RTL433.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
