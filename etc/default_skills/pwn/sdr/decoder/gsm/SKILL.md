---
name: pwn-sdr-decoder-gsm
description: Drive PWN::SDR::Decoder::GSM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::GSM
  source: pwn/sdr/decoder/gsm.rb
---

# PWN::SDR::Decoder::GSM

GSM (2G) true-air FCCH/SCH decoder. 270.833 kbit/s GMSK. FCCH burst = 148 all-zero bits → a pure +67.708 kHz tone for ~547 μs. Detect via variance-dip on the FM discriminator (PWN::FFI::Liquid.freq_demod), estimate carrier offset from mean deviation, then correlate the SCH 64-bit extended training sequence 8 timeslots later and recover the 6-bit BSIC (NCC/BCC) + 19-bit reduced frame number (T1/T2/T3'). Emits {event:'fcch'|'sch', freq_offset_hz:, bsic:, ncc:, bcc:, rfn:}.

## When to use

Call `PWN::SDR::Decoder::GSM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/gsm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::GSM.help
PWN::SDR::Decoder::GSM.viterbi_decode(opts)
```

## Public methods

- `viterbi_decode`
- `parity`
- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/gsm.rb`

## Verification

`PWN::SDR::Decoder::GSM.respond_to?(:viterbi_decode)` after the
module is loaded. Read the source for parameter names.
