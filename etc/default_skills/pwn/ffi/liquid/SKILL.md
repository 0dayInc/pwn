---
name: pwn-ffi-liquid
description: Drive PWN::FFI::Liquid from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::Liquid
  source: pwn/ffi/liquid.rb
---

# PWN::FFI::Liquid

Thin liquid-dsp binding. Provides the high-level DSP building blocks that PWN::SDR::Decoder::* needs beyond pure-Ruby primitives: FM / frequency demodulation, multi-stage arbitrary resampling, and Kaiser FIR filters. Opaque liquid handles are held as FFI::Pointer and always freed in an ensure — no compile step, no shells. If libliquid is absent `.available?` is false and DSP falls back to pure Ruby. Complex samples use the GCC float _Complex ABI: interleaved float[2] (re, im) per sample, which is how liquid_float_complex is laid out under LIQUID_DEFINE_COMPLEX.

## When to use

Call `PWN::FFI::Liquid` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/liquid.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::Liquid.help
PWN::FFI::Liquid.available(opts)
```

## Public methods

- `available`
- `freq_demod`
- `resample`
- `fir_kaiser`
- `dc_block`
- `resample_iq`
- `mix_down`
- `gmsk_demod`
- `mfsk_demod`
- `authors`
- `help`
- `available?`
- `firfilt_rrrf_create_dc_blocker`
- `firfilt_rrrf_create_kaiser`
- `firfilt_rrrf_destroy`
- `firfilt_rrrf_execute_block`
- `firfilt_rrrf_reset`
- `freqdem_create`
- `freqdem_demodulate_block`
- `freqdem_destroy`
- `freqdem_print`
- `freqdem_reset`
- `fskdem_create`
- `fskdem_demodulate`
- `fskdem_destroy`
- `gmskdem_create`
- `gmskdem_demodulate`
- `gmskdem_destroy`
- `gmskdem_reset`
- `load_error`
- `msresamp_crcf_create`
- `msresamp_crcf_destroy`
- `msresamp_crcf_execute`
- `msresamp_rrrf_create`
- `msresamp_rrrf_destroy`
- `msresamp_rrrf_execute`
- `msresamp_rrrf_get_delay`
- `msresamp_rrrf_get_num_output`
- `msresamp_rrrf_get_rate`
- `msresamp_rrrf_reset`
- `nco_crcf_create`
- `nco_crcf_destroy`
- `nco_crcf_mix_block_down`
- `nco_crcf_set_frequency`

## Source

`pwn/ffi/liquid.rb`

## Verification

`PWN::FFI::Liquid.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
