---
name: pwn-ffi-rtlsdr
description: Drive PWN::FFI::RTLSdr from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::RTLSdr
  source: pwn/ffi/rtl_sdr.rb
---

# PWN::FFI::RTLSdr

Thin librtlsdr binding (no -dev headers required — symbols resolved from the installed shared object). Control-plane + blocking `read_sync` so PWN::SDR::Decoder::* / Extrospection probe_rf can pull raw u8 I/Q without shelling out to `rtl_sdr`. If librtlsdr is missing `.available?` is false and callers fall back.

## When to use

Call `PWN::FFI::RTLSdr` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/rtl_sdr.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::RTLSdr.help
PWN::FFI::RTLSdr.available(opts)
```

## Public methods

- `available`
- `list_devices`
- `open`
- `close`
- `configure`
- `read_sync`
- `tuner_gains`
- `authors`
- `help`
- `available?`
- `load_error`
- `rtlsdr_close`
- `rtlsdr_get_center_freq`
- `rtlsdr_get_device_count`
- `rtlsdr_get_device_name`
- `rtlsdr_get_device_usb_strings`
- `rtlsdr_get_sample_rate`
- `rtlsdr_get_tuner_gains`
- `rtlsdr_open`
- `rtlsdr_read_sync`
- `rtlsdr_reset_buffer`
- `rtlsdr_set_agc_mode`
- `rtlsdr_set_center_freq`
- `rtlsdr_set_freq_correction`
- `rtlsdr_set_sample_rate`
- `rtlsdr_set_tuner_gain`
- `rtlsdr_set_tuner_gain_mode`

## Source

`pwn/ffi/rtl_sdr.rb`

## Verification

`PWN::FFI::RTLSdr.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
