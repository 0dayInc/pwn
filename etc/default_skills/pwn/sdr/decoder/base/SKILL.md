---
name: pwn-sdr-decoder-base
description: Drive PWN::SDR::Decoder::Base from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Base
  source: pwn/sdr/decoder/base.rb
---

# PWN::SDR::Decoder::Base

Shared, 100 % Ruby-native pipeline plumbing for every PWN::SDR::Decoder::* module. Three entry points, none of which shell out to any external binary: run_native — Bind the GQRX 48 kHz s16le mono UDP audio tap, unpack the samples with PWN::SDR::Decoder::DSP, hand each chunk to a caller-supplied `demod:` object that responds to `#feed(samples, &emit)`. Every Hash the demodulator emits is merged with freq_obj, JSON- pretty-printed, JSONL-logged, and shown on the spinner. [ENTER] stops cleanly. run_iq — True-air path. Opens a real SDR front-end via PWN::FFI::{RTLSdr,HackRF,AdalmPluto,SoapySDR} (or reads a capture file), streams interleaved I/Q into a demod that responds to `#feed_iq(iq, rate:, &emit)` (or `#feed` after optional FM-demod). Falls back to run_detector when no hardware/file source is present so the operator still gets structured output. run_detector — For protocols whose bit-rate/bandwidth cannot be recovered from a 48 kHz demodulated-audio tap (GSM, LTE, ADS-B, WiFi, LoRa, GPS, DECT, ZigBee, Bluetooth, Iridium, P25, ISM/RFID …). Pure-Ruby energy / burst characterizer: polls GQRX `l STRENGTH`, and (when the UDP tap is enabled) computes RMS-dBFS on the audio. Emits `{event: 'burst', dbfs:, duration_ms:}` frames whenever the signal crosses an adaptive threshold, so the operator still gets structured, logged intel without ANY external decoding binary.

## When to use

Call `PWN::SDR::Decoder::Base` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/base.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Base.help
PWN::SDR::Decoder::Base.run_native(opts)
```

## Public methods

- `run_native`
- `run_detector`
- `match_line`
- `resolve_iq_source`
- `read_iq_chunk`
- `unpack_iq`
- `close_iq_source`
- `run_iq`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/base.rb`

## Verification

`PWN::SDR::Decoder::Base.respond_to?(:run_native)` after the
module is loaded. Read the source for parameter names.
