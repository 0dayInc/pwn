---
name: pwn-plugins-serial
description: Drive PWN::Plugins::Serial from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Serial
  source: pwn/plugins/serial.rb
---

# PWN::Plugins::Serial

This plugin is used for interacting with serial devices including, but not limited to, modems (including cellphone radios), legacy equipment, arduinos, & other misc ftdi devices

## When to use

Call `PWN::Plugins::Serial` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/serial.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Serial.help
PWN::Plugins::Serial.connect(opts)
```

## Public methods

- `connect`
- `get_line_state`
- `get_modem_params`
- `request`
- `response`
- `dump_session_data`
- `flush_session_data`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/serial.rb`

## Verification

`PWN::Plugins::Serial.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
