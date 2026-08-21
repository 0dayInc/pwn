---
name: pwn-sdr-decoder-pager
description: Drive PWN::SDR::Decoder::Pager from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::Pager
  source: pwn/sdr/decoder/pager.rb
---

# PWN::SDR::Decoder::Pager

Pure-Ruby combined pager decoder for the mixed-protocol `pager_all` band plan. Feeds every incoming 48 kHz audio chunk to BOTH the native POCSAG and FLEX demodulators concurrently; whichever locks emits messages. No `multimon-ng`, no `sox`.

## When to use

Call `PWN::SDR::Decoder::Pager` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/pager.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::Pager.help
PWN::SDR::Decoder::Pager.decode(opts)
```

## Public methods

- `decode`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/pager.rb`

## Verification

`PWN::SDR::Decoder::Pager.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
