---
name: pwn-ffi-volk
description: Drive PWN::FFI::Volk from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::Volk
  source: pwn/ffi/volk.rb
---

# PWN::FFI::Volk

Thin VOLK (Vector-Optimized Library of Kernels) binding. Dispatches to SIMD kernels (SSE/AVX/NEON/…) when the host provides them. Used by PWN::SDR::Decoder::DSP hot paths so MHz-rate I/Q work stays off the Ruby GC heap while orchestration remains pure Ruby. Nothing here shells out and nothing is compiled at gem-install time — if libvolk is missing, `.available?` is false and callers fall back.

## When to use

Call `PWN::FFI::Volk` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/volk.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::Volk.help
PWN::FFI::Volk.available(opts)
```

## Public methods

- `available`
- `unpack_s16le`
- `accumulate`
- `magnitude_squared`
- `sqrt`
- `scale`
- `dot_prod`
- `authors`
- `help`

## Source

`pwn/ffi/volk.rb`

## Verification

`PWN::FFI::Volk.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
