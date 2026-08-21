---
name: pwn-sdr-decoder-rfid
description: Drive PWN::SDR::Decoder::RFID from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::RFID
  source: pwn/sdr/decoder/rfid.rb
---

# PWN::SDR::Decoder::RFID

True-air + detector-fallback decoder for RFID. Prefers PWN::FFI I/Q (RTL-SDR / ADALM-Pluto / HackRF / capture file) via Base.run_iq; degrades to Base.run_detector with no hardware.

## When to use

Call `PWN::SDR::Decoder::RFID` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/rfid.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::RFID.help
PWN::SDR::Decoder::RFID.decode(opts)
```

## Public methods

- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/rfid.rb`

## Verification

`PWN::SDR::Decoder::RFID.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
