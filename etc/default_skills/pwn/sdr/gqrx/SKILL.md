---
name: pwn-sdr-gqrx
description: Drive PWN::SDR::GQRX from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::GQRX
  source: pwn/sdr/gqrx.rb
---

# PWN::SDR::GQRX

This plugin interacts with the remote control interface of GQRX.

## When to use

Call `PWN::SDR::GQRX` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/gqrx.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::GQRX.help
PWN::SDR::GQRX.cmd(opts)
```

## Public methods

- `cmd`
- `connect`
- `init_freq`
- `scan_range`
- `analyze_scan`
- `analyze_log`
- `listen_udp`
- `disconnect_udp`
- `record`
- `stop_recording`
- `disconnect`
- `config_path`
- `read_input_config`
- `device_input_rates`
- `nearest_input_rate`
- `set_input_rate`
- `apply_band_plan_input_rate`
- `restart_gqrx`
- `get_spectrum_snapshot`
- `fast_scan_range`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sdr/gqrx.rb`

## Verification

`PWN::SDR::GQRX.respond_to?(:cmd)` after the
module is loaded. Read the source for parameter names.
