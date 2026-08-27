---
name: pwn-ffi-hackrf
description: Drive PWN::FFI::HackRF from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::FFI::HackRF
  source: pwn/ffi/hack_rf.rb
---

# PWN::FFI::HackRF

Thin libhackrf binding for inventory / RX of raw I/Q. Intentionally control-plane first: init/open/tune/rate/gains + one-shot sync-style helpers used by Extrospection `probe_rf` and by wideband PWN::SDR::Decoder::* modules that need real I/Q (not GQRX audio). Streaming callbacks stay opt-in — Ruby GC must not run on the libusb transfer thread, so call sites that need continuous RX should buffer into a Queue from a dedicated thread.

## When to use

Call `PWN::FFI::HackRF` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ffi/hack_rf.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::FFI::HackRF.help
PWN::FFI::HackRF.available(opts)
```

## Public methods

- `available`
- `info`
- `open`
- `close`
- `configure`
- `device_info`
- `start_rx`
- `read_sync`
- `stop_rx`
- `capture`
- `authors`
- `help`
- `available?`
- `hackrf_board_id_name`
- `hackrf_board_id_read`
- `hackrf_close`
- `hackrf_error_name`
- `hackrf_exit`
- `hackrf_init`
- `hackrf_is_streaming`
- `hackrf_library_release`
- `hackrf_library_version`
- `hackrf_open`
- `hackrf_open_by_serial`
- `hackrf_set_amp_enable`
- `hackrf_set_baseband_filter_bandwidth`
- `hackrf_set_freq`
- `hackrf_set_lna_gain`
- `hackrf_set_sample_rate`
- `hackrf_set_vga_gain`
- `hackrf_start_rx`
- `hackrf_stop_rx`
- `hackrf_version_string_read`
- `load_error`

## Source

`pwn/ffi/hack_rf.rb`

## Verification

`PWN::FFI::HackRF.respond_to?(:available)` after the
module is loaded. Read the source for parameter names.
