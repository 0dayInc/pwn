---
name: pwn-ffi-soapysdr
description: Drive PWN::FFI::SoapySDR from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::SoapySDR
  source: pwn/ffi/soapy_sdr.rb
---

# PWN::FFI::SoapySDR

Thin SoapySDR C-API binding (libSoapySDR). Inventory-focused first — enumerate devices and report API version so Extrospection `probe_rf` can list every Soapy-backed front-end (RTL-SDR, HackRF, Airspy, Pluto, UHD, …) without shelling out to `SoapySDRUtil`. Streaming: open/configure/start_rx/read_sync/stop_rx/close for CS16 I/Q so PWN::SDR::Decoder::Base.run_iq can true-air decode from ANY Soapy-backed front-end. Missing lib -> .available? false, callers fall back to pure Ruby / other PWN::FFI front-ends.

## When to use

Call `PWN::FFI::SoapySDR` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/soapy_sdr.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::SoapySDR.help
PWN::FFI::SoapySDR.available(opts)
```

## Public methods

- `available`
- `info`
- `list_devices`
- `make`
- `unmake`
- `device_keys`
- `open`
- `configure`
- `start_rx`
- `read_sync`
- `stop_rx`
- `close`
- `authors`
- `help`

## Source

`pwn/ffi/soapy_sdr.rb`

## Verification

`PWN::FFI::SoapySDR.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
