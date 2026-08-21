---
name: pwn-sdr-decoder-iridium
description: Drive PWN::SDR::Decoder::Iridium from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Iridium
  source: pwn/sdr/decoder/iridium.rb
---

# PWN::SDR::Decoder::Iridium

True-air + detector-fallback decoder for Iridium. Prefers PWN::FFI I/Q (RTL-SDR / ADALM-Pluto / HackRF / capture file) via Base.run_iq; degrades to Base.run_detector with no hardware.

## When to use

Call `PWN::SDR::Decoder::Iridium` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/iridium.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Iridium.help
PWN::SDR::Decoder::Iridium.decode(opts)
```

## Public methods

- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/iridium.rb`

## Verification

`PWN::SDR::Decoder::Iridium.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
