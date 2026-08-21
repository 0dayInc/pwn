---
name: pwn-sdr-decoder-dect
description: Drive PWN::SDR::Decoder::DECT from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::DECT
  source: pwn/sdr/decoder/dect.rb
---

# PWN::SDR::Decoder::DECT

DECT (ETSI EN 300 175) true-air decoder. 1.152 Mbit/s GFSK, 24-slot / 10 ms TDMA. I/Q → PWN::FFI::Liquid gmskdem (or DSP.fm_demod_iq→NRZ) → hunt 32-bit S-field (16-bit preamble + 16-bit sync 0xE98A FP / 0x1675 PP) → A-field (64 bits: 8-bit header + 40-bit tail + 16-bit R-CRC) → RFPI extraction on Nt/Qt tails. Emits {rfpi:, role:, slot_est:, crc_ok:}.

## When to use

Call `PWN::SDR::Decoder::DECT` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/dect.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::DECT.help
PWN::SDR::Decoder::DECT.decode(opts)
```

## Public methods

- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/dect.rb`

## Verification

`PWN::SDR::Decoder::DECT.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
