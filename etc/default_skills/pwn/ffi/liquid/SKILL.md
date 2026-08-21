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

## Source

`pwn/ffi/liquid.rb`

## Verification

`PWN::FFI::Liquid.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
