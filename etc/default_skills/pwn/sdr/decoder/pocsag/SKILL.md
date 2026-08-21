---
name: pwn-sdr-decoder-pocsag
description: Drive PWN::SDR::Decoder::POCSAG from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::POCSAG
  source: pwn/sdr/decoder/pocsag.rb
---

# PWN::SDR::Decoder::POCSAG

Pure-Ruby POCSAG (CCIR Radiopaging Code No. 1) decoder. GQRX supplies NBFM-discriminator audio on its 48 kHz UDP tap; for a 2-FSK pager channel that is already an NRZ baseband whose sign encodes the bit. This module NRZ-slices at 512/1200/2400 baud, locks onto the 32-bit Frame Sync Codeword (0x7CD215D8), then walks each 8-frame batch of BCH(31,21)+parity codewords, extracting address (RIC/capcode + function bits) and message codewords (numeric BCD or 7-bit ASCII). No `multimon-ng`, no `sox`.

## When to use

Call `PWN::SDR::Decoder::POCSAG` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/pocsag.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::POCSAG.help
PWN::SDR::Decoder::POCSAG.decode_bits(opts)
```

## Public methods

- `decode_bits`
- `assemble`
- `numeric_decode`
- `alpha_decode`
- `decode`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/pocsag.rb`

## Verification

`PWN::SDR::Decoder::POCSAG.respond_to?(:decode_bits)` after the
module is loaded. Read the source for parameter names.
