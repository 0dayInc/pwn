---
name: pwn-ffi-adalmpluto-ad9361
description: Drive PWN::FFI::AdalmPluto::Ad9361 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::AdalmPluto::Ad9361
  source: pwn/ffi/adalm_pluto.rb
---

# PWN::FFI::AdalmPluto::Ad9361

Thin libiio binding specialised for the ADALM-PLUTO (AD9363). Control-plane + blocking RX of interleaved CS16 I/Q so PWN::SDR::Decoder::* can pull MHz-rate complex samples without GQRX's 48 kHz audio tap and without shelling out to iio_*. libad9361 is used only for optional bb_rate helpers when present. If libiio is missing `.available?` is false and callers fall back to RTLSdr / HackRF / SoapySDR / pure-Ruby detector paths. Default URI tries USB (local) first: "ip:192.168.2.1" is the stock Ethernet/USB-gadget address of an unconfigured Pluto.

## When to use

Call `PWN::FFI::AdalmPluto::Ad9361` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/adalm_pluto.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::AdalmPluto::Ad9361.help
PWN::FFI::AdalmPluto::Ad9361.available(opts)
```

## Public methods

- `available`
- `info`
- `list_uris`
- `open`
- `close`
- `device_info`
- `configure`
- `start_rx`
- `read_sync`
- `stop_rx`
- `capture`
- `authors`
- `help`
- `ad9361_set_bb_rate`
- `load_error`

## Source

`pwn/ffi/adalm_pluto.rb`

## Verification

`PWN::FFI::AdalmPluto::Ad9361.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
