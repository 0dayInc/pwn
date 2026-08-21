---
name: pwn-sdr-decoder-bluetooth
description: Drive PWN::SDR::Decoder::Bluetooth from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Bluetooth
  source: pwn/sdr/decoder/bluetooth.rb
---

# PWN::SDR::Decoder::Bluetooth

Bluetooth LE (& BR/EDR sync-trailer) true-air decoder. I/Q → PWN::FFI::Liquid.gmsk_demod (or DSP.fm_demod_iq→NRZ) at 1 Mbit/s → hunt LSB-first Access Address (adv = 0x8E89BED6) → dewhiten (7-bit LFSR seeded ch|0x40) → PDU header (type/len) → AdvA (6 bytes) → CRC-24 (poly 0x65B, init 0x555555). Emits per-PDU {access_addr:, pdu_type:, adv_addr:, crc_ok:} — ubertooth-parity advertising sniff with no external binary.

## When to use

Call `PWN::SDR::Decoder::Bluetooth` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/bluetooth.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Bluetooth.help
PWN::SDR::Decoder::Bluetooth.ble_crc24(opts)
```

## Public methods

- `ble_crc24`
- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/bluetooth.rb`

## Verification

`PWN::SDR::Decoder::Bluetooth.respond_to?(:ble_crc24)` after the
module is loaded. Read the source for parameter names.
