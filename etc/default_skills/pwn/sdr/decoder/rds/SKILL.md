---
name: pwn-sdr-decoder-rds
description: Drive PWN::SDR::Decoder::RDS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::Decoder::RDS
  source: pwn/sdr/decoder/rds.rb
---

# PWN::SDR::Decoder::RDS

RDS Decoder Module for FM Radio Signals. Two entry points: .sample — non-interactive structured Hash (agents / cron / tools) .decode — interactive TTY spinner (human REPL via GQRX.init_freq) Both share the same GQRX RDS protocol path (U RDS, p RDS_PI / PS_NAME / RADIOTEXT). .sample is the canonical mid-layer API that Extrospection and any other automation should call.

## When to use

Call `PWN::SDR::Decoder::RDS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/decoder/rds.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::Decoder::RDS.help
PWN::SDR::Decoder::RDS.sample(opts)
```

## Public methods

- `sample`
- `decode`
- `authors`
- `help`

## Source

`pwn/sdr/decoder/rds.rb`

## Verification

`PWN::SDR::Decoder::RDS.respond_to?(:sample)` after the
module is loaded. Read the source for parameter names.
