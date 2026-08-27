---
name: pwn-sdr-decoder-adsb
description: Drive PWN::SDR::Decoder::ADSB from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::ADSB
  source: pwn/sdr/decoder/adsb.rb
---

# PWN::SDR::Decoder::ADSB

ADS-B (1090 MHz Mode-S / 978 MHz UAT) true-air decoder. Prefer PWN::FFI::{RTLSdr,AdalmPluto,HackRF} at ≥2 Msps and run a pure-Ruby Mode-S preamble correlator + 112-bit PPM slicer over magnitude samples. Falls back to Base.run_detector energy mode when no I/Q source is available. Offline SBS-1 CSV → .parse_line.

## When to use

Call `PWN::SDR::Decoder::ADSB` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/adsb.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::ADSB.help
PWN::SDR::Decoder::ADSB.crc24(opts)
```

## Public methods

- `crc24`
- `crc_ok`
- `decode_modes`
- `ais_char`
- `modes_altitude`
- `decode`
- `parse_line`
- `authors`
- `help`
- `crc_ok?`

## Source

`pwn/sdr/decoder/adsb.rb`

## Verification

`PWN::SDR::Decoder::ADSB.respond_to?(:crc24)` after the
module is loaded. Read the source for parameter names.
