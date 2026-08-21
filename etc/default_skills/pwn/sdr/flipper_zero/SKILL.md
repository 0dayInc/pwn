---
name: pwn-sdr-flipperzero
description: Drive PWN::SDR::FlipperZero from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::FlipperZero
  source: pwn/sdr/flipper_zero.rb
---

# PWN::SDR::FlipperZero

This plugin is used for interacting with Bus Pirate v3.6 This plugin may be compatible with other versions, however, has not been tested with anything other than v3.6.

## When to use

Call `PWN::SDR::FlipperZero` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/flipper_zero.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::FlipperZero.help
PWN::SDR::FlipperZero.connect_via_screen(opts)
```

## Public methods

- `connect_via_screen`
- `connect`
- `request`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/sdr/flipper_zero.rb`

## Verification

`PWN::SDR::FlipperZero.respond_to?(:connect_via_screen)` after the
module is loaded. Read the source for parameter names.
