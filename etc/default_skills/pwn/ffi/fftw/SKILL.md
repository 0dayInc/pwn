---
name: pwn-ffi-fftw
description: Drive PWN::FFI::FFTW from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::FFTW
  source: pwn/ffi/fftw.rb
---

# PWN::FFI::FFTW

Thin single-precision FFTW3 binding (`libfftw3f`). Used by PWN::SDR::* spectrum work (GQRX FFT snapshots, wideband energy detectors) when MHz-rate FFTs outgrow pure-Ruby DFT. Missing library degrades cleanly via `.available?` — callers keep pure-Ruby fallbacks. No compile step at gem install; no shells. Plans are built with FFTW_ESTIMATE so first-call latency stays acceptable for REPL use.

## When to use

Call `PWN::FFI::FFTW` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/fftw.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::FFTW.help
PWN::FFI::FFTW.available(opts)
```

## Public methods

- `available`
- `rfft`
- `rfft_magnitude`
- `rfft_power_db`
- `cfft`
- `authors`
- `help`

## Source

`pwn/ffi/fftw.rb`

## Verification

`PWN::FFI::FFTW.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
