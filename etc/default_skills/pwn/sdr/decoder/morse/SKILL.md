---
name: pwn-sdr-decoder-morse
description: Drive PWN::SDR::Decoder::Morse from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Morse
  source: pwn/sdr/decoder/morse.rb
---

# PWN::SDR::Decoder::Morse

Pure-Ruby CW / Morse decoder for the amateur CW sub-bands. GQRX's CW/USB demodulator produces a ~600–800 Hz sidetone in the 48 kHz UDP audio stream. This module envelope-detects the tone with a state-preserving single-pole low-pass, adaptively thresholds it into on/off runs, classifies each run as dit / dah / char-gap / word-gap by timing, and looks the resulting `.-` sequences up in DSP::MORSE_TABLE. No `multimon-ng`, no `sox`.

## When to use

Call `PWN::SDR::Decoder::Morse` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/morse.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Morse.help
PWN::SDR::Decoder::Morse.decode(opts)
```

## Public methods

- `decode`
- `decode_string`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/morse.rb`

## Verification

`PWN::SDR::Decoder::Morse.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
