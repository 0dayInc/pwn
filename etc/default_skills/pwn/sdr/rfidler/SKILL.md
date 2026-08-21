---
name: pwn-sdr-rfidler
description: Drive PWN::SDR::RFIDler from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::RFIDler
  source: pwn/sdr/rfidler.rb
---

# PWN::SDR::RFIDler

This plugin is used for interacting with an RFIDler using the the screen command as a terminal emulator.

## When to use

Call `PWN::SDR::RFIDler` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/rfidler.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::RFIDler.help
PWN::SDR::RFIDler.connect_via_screen(opts)
```

## Public methods

- `connect_via_screen`
- `authors`
- `help`

## Source

`pwn/sdr/rfidler.rb`

## Verification

`PWN::SDR::RFIDler.respond_to?(:connect_via_screen)` after the
module is loaded. Read the source for parameter names.
