---
name: pwn-sdr-decoder-lte
description: Drive PWN::SDR::Decoder::LTE from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::LTE
  source: pwn/sdr/decoder/lte.rb
---

# PWN::SDR::Decoder::LTE

LTE (E-UTRA) true-air PSS/SSS cell search. I/Q resampled to 1.92 Msps (128-FFT grid), time-domain PSS correlation against Zadoff-Chu roots {25,29,34} → N_ID_2 ∈ {0,1,2} + half-frame timing + coarse CFO. SSS m-sequence pair 5 symbols earlier → N_ID_1 ∈ 0..167 → PCI = 3·N_ID_1 + N_ID_2. All FFTs via PWN::FFI::FFTW; falls back to naive DFT for small N.

## When to use

Call `PWN::SDR::Decoder::LTE` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/lte.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::LTE.help
PWN::SDR::Decoder::LTE.sss_indices(opts)
```

## Public methods

- `sss_indices`
- `mseq`
- `cseq`
- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/lte.rb`

## Verification

`PWN::SDR::Decoder::LTE.respond_to?(:sss_indices)` after the
module is loaded. Read the source for parameter names.
