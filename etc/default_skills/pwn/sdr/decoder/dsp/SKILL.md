---
name: pwn-sdr-decoder-dsp
description: Drive PWN::SDR::Decoder::DSP from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::DSP
  source: pwn/sdr/decoder/dsp.rb
---

# PWN::SDR::Decoder::DSP

DSP primitives shared by every PWN::SDR::Decoder::* module. Default path is pure Ruby operating on Array<Float> samples normalised to -1.0..1.0 (48 kHz s16le mono from GQRX UDP — no `sox` / `multimon-ng` / `minimodem` dependency). When the matching system library is present the hot paths transparently accelerate via PWN::FFI::{Volk,Liquid,FFTW}: unpack_s16le → PWN::FFI::Volk (SIMD s16→f32 convert) unpack_cs16le → pure / Volk path (interleaved I/Q s16 → f32) unpack_cu8 → pure path (RTL-SDR u8 I/Q → f32) resample → PWN::FFI::Liquid (msresamp multi-stage) dc_block → PWN::FFI::Liquid (firfilt DC blocker) rms_dbfs → PWN::FFI::Volk (accumulate of squares) mag_sq / fm_demod_iq → true-air I/Q paths for Base.run_iq Each accelerated method falls back to the pure-Ruby body when the backend is missing or raises, so decoders never require a native library at install time. Force pure Ruby for testing with PWN::SDR::Decoder::DSP.native = false

## When to use

Call `PWN::SDR::Decoder::DSP` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/dsp.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::DSP.help
PWN::SDR::Decoder::DSP.unpack_s16le(opts)
```

## Public methods

- `unpack_s16le`
- `resample`
- `goertzel`
- `envelope`
- `dc_block`
- `nrz_slice`
- `envelope_signed`
- `fsk_slice`
- `find_sync`
- `bits_to_int`
- `even_parity_ok`
- `bch_31_21_syndrome`
- `baudot_decode`
- `rms_dbfs`
- `unpack_cs16le`
- `unpack_cu8`
- `mag_sq`
- `fm_demod_iq`
- `iq_rms_dbfs`
- `correlate`
- `resample_iq`
- `mix_iq`
- `gfsk_slice`
- `slice_4fsk`
- `manchester_decode`
- `diff_decode`
- `bytes_from_bits`
- `crc16`
- `whiten_lfsr`
- `ook_pulses`
- `cfft_mag`
- `dft_naive`
- `zadoff_chu`
- `ca_code`
- `cmul`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/dsp.rb`

## Verification

`PWN::SDR::Decoder::DSP.respond_to?(:unpack_s16le)` after the
module is loaded. Read the source for parameter names.
