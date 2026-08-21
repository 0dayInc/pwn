---
name: pwn-sdr-decoder-rtty
description: Drive PWN::SDR::Decoder::RTTY from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::RTTY
  source: pwn/sdr/decoder/rtty.rb
---

# PWN::SDR::Decoder::RTTY

Pure-Ruby RTTY (Radioteletype, ITA2/Baudot) decoder. Amateur RTTY is 45.45 baud 2-FSK with a 170 Hz shift; on USB the convention is mark ≈ 2125 Hz, space ≈ 2295 Hz in the demodulated audio. This module runs a per-symbol Goertzel on both tones, frames 1-start / 5-data / 1.5-stop asynchronously, and decodes ITA2 via DSP::BAUDOT_LTRS/FIGS. No `minimodem`, no `sox`.

## When to use

Call `PWN::SDR::Decoder::RTTY` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/rtty.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::RTTY.help
PWN::SDR::Decoder::RTTY.decode(opts)
```

## Public methods

- `decode`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/rtty.rb`

## Verification

`PWN::SDR::Decoder::RTTY.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
