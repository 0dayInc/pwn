---
name: pwn-sdr-sonmicrorfid
description: Drive PWN::SDR::SonMicroRFID from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::SonMicroRFID
  source: pwn/sdr/son_micro_rfid.rb
---

# PWN::SDR::SonMicroRFID

This plugin is used for interacting with a SonMicro SM132 USB RFID Reader / Writer (PCB V3) && SM2330-USB Rev.0

## When to use

Call `PWN::SDR::SonMicroRFID` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/son_micro_rfid.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::SonMicroRFID.help
PWN::SDR::SonMicroRFID.connect(opts)
```

## Public methods

- `connect`
- `list_cmds`
- `list_params`
- `exec`
- `read_tag`
- `write_tag`
- `backup_tag`
- `clone_tag`
- `load_tag_from_file`
- `update_tag`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/sdr/son_micro_rfid.rb`

## Verification

`PWN::SDR::SonMicroRFID.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
