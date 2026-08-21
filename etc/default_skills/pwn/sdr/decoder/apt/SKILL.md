---
name: pwn-sdr-decoder-apt
description: Drive PWN::SDR::Decoder::APT from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::APT
  source: pwn/sdr/decoder/apt.rb
---

# PWN::SDR::Decoder::APT

Pure-Ruby NOAA APT (Automatic Picture Transmission) decoder for the 137 MHz polar-orbiting weather satellites (NOAA-15/18/19). APT is a 2400 Hz AM subcarrier inside a ~34 kHz-wide FM downlink carrying two 909-pixel image channels at 2 lines/second (4160 words/line). This module envelope-demodulates the 2400 Hz carrier from GQRX's 48 kHz UDP audio, resamples to 4160 words/sec, aligns each line on the 7-pulse Sync-A pattern, and appends the resulting 8-bit greyscale rows to a Netpbm PGM (P5) file — all in Ruby. No `sox`, no `noaa-apt`.

## When to use

Call `PWN::SDR::Decoder::APT` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/apt.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::APT.help
PWN::SDR::Decoder::APT.decode(opts)
```

## Public methods

- `decode`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/apt.rb`

## Verification

`PWN::SDR::Decoder::APT.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
