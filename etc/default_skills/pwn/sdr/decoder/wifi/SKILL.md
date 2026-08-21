---
name: pwn-sdr-decoder-wifi
description: Drive PWN::SDR::Decoder::WiFi from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::WiFi
  source: pwn/sdr/decoder/wifi.rb
---

# PWN::SDR::Decoder::WiFi

True-air + detector-fallback decoder for WiFi. Prefers PWN::FFI I/Q (RTL-SDR / ADALM-Pluto / HackRF / capture file) via Base.run_iq; degrades to Base.run_detector with no hardware.

## When to use

Call `PWN::SDR::Decoder::WiFi` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/wifi.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::WiFi.help
PWN::SDR::Decoder::WiFi.decode(opts)
```

## Public methods

- `decode`
- `parse_line`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/wifi.rb`

## Verification

`PWN::SDR::Decoder::WiFi.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
