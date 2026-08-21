---
name: pwn-sdr-decoder-zigbee
description: Drive PWN::SDR::Decoder::ZigBee from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::ZigBee
  source: pwn/sdr/decoder/zigbee.rb
---

# PWN::SDR::Decoder::ZigBee

IEEE 802.15.4 O-QPSK (2.4 GHz ZigBee/Thread) true-air decoder. 2 Mchip/s half-sine O-QPSK ≡ MSK, so I/Q → PWN::FFI::Liquid gmskdem (BT=0.5) at 2 Msps → chip stream. Each 4-bit symbol maps to a 32-chip PN sequence (Table 73, IEEE 802.15.4-2011); soft- correlate every 32 chips against the 16 sequences → symbols → nibbles → bytes. Hunt SHR (4×0x00 preamble + SFD 0xA7) → PHR len → MHR (FCF/seq/PAN/addr) → FCS (CRC-16-KERMIT). Emits per-frame {pan_id:, src:, dst:, frame_type:, len:, fcs_ok:}.

## When to use

Call `PWN::SDR::Decoder::ZigBee` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/zigbee.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::ZigBee.help
PWN::SDR::Decoder::ZigBee.decode(opts)
```

## Public methods

- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/zigbee.rb`

## Verification

`PWN::SDR::Decoder::ZigBee.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
