---
name: pwn-sdr-decoder-flex
description: Drive PWN::SDR::Decoder::Flex from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Flex
  source: pwn/sdr/decoder/flex.rb
---

# PWN::SDR::Decoder::Flex

Pure-Ruby FLEX™ pager decoder. FLEX is Motorola's synchronous paging protocol running at 1600 or 3200 symbols/s in 2- or 4-level FSK. GQRX's NBFM discriminator audio (48 kHz UDP tap) is fed into a per-sample PLL symbol clock, 4-level quantised, and driven through the Sync-1 → FIW → Sync-2 → 11-block state machine. All four interleaved phases (A/B/C/D) are de-interleaved into 88 × 32-bit BCH(31,21)+parity codewords, error corrected, and walked (BIW → address → vector → message words) to recover capcode + alphanumeric / numeric / binary payloads. Algorithm is a clean-room Ruby port of the reference behavior in multimon-ng `demod_flex.c` (GPLv2), verified bit-exact against a live 929.625 MHz 3200/4 capture: sync 0xDEA0, FIW cycle 10 frame 70, 88/88 BCH-clean words per phase, capcodes 4294949118 / 002064207 / 002064227 all matching multimon-ng ground truth. No `multimon-ng`, no `sox` — 100 % Ruby.

## When to use

Call `PWN::SDR::Decoder::Flex` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/flex.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Flex.help
PWN::SDR::Decoder::Flex.sync_check(opts)
```

## Public methods

- `sync_check`
- `popcnt`
- `even_parity`
- `bch_syn`
- `bch_fix`
- `emit_phase`
- `alpha_decode`
- `numeric_decode`
- `hex_decode`
- `decode`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/flex.rb`

## Verification

`PWN::SDR::Decoder::Flex.respond_to?(:sync_check)` after the
module is loaded. Read the source for parameter names.
