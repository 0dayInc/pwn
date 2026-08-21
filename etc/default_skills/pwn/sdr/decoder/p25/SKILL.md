---
name: pwn-sdr-decoder-p25
description: Drive PWN::SDR::Decoder::P25 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::P25
  source: pwn/sdr/decoder/p25.rb
---

# PWN::SDR::Decoder::P25

APCO Project 25 Phase-1 (C4FM) true-air decoder. I/Q → PWN::FFI::Liquid.freq_demod (or DSP.fm_demod_iq) → resample to 48 kHz → 4-level slice at 4800 sym/s → dibits → hunt the 24-symbol Frame Sync (0x5575F5FF77FF) → recover the 64-bit NID (12-bit NAC + 4-bit DUID + BCH(63,16,23) parity). Emits {nac:, duid:, duid_name:} per frame — the same intel OP25 / DSD show — with no external binary.

## When to use

Call `PWN::SDR::Decoder::P25` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/p25.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::P25.help
PWN::SDR::Decoder::P25.decode(opts)
```

## Public methods

- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/p25.rb`

## Verification

`PWN::SDR::Decoder::P25.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
