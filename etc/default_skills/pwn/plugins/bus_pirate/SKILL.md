---
name: pwn-plugins-buspirate
description: Drive PWN::Plugins::BusPirate from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BusPirate
  source: pwn/plugins/bus_pirate.rb
---

# PWN::Plugins::BusPirate

This plugin is used for interacting with Bus Pirate v3.6 This plugin may be compatible with other versions, however, has not been tested with anything other than v3.6.

## When to use

Call `PWN::Plugins::BusPirate` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/bus_pirate.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BusPirate.help
PWN::Plugins::BusPirate.connect_via_screen(opts)
```

## Public methods

- `connect_via_screen`
- `connect`
- `init_mode`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/plugins/bus_pirate.rb`

## Verification

`PWN::Plugins::BusPirate.respond_to?(:connect_via_screen)` after the
module is loaded. Read the source for parameter names.
