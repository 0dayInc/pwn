---
name: pwn-plugins-vin
description: Drive PWN::Plugins::VIN from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::VIN
  source: pwn/plugins/vin.rb
---

# PWN::Plugins::VIN

This plugin provides useful VIN generation and decoding capabilities using the NHTSA vPIC API

## When to use

Call `PWN::Plugins::VIN` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/vin.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::VIN.help
PWN::Plugins::VIN.get_all_manufacturers(opts)
```

## Public methods

- `get_all_manufacturers`
- `get_all_makes`
- `get_wmis_for_manufacturer`
- `decode_wmi`
- `decode_vin`
- `get_models_for_make`
- `get_models_for_make_year`
- `get_vehicle_types_for_make`
- `get_manufacturer_details`
- `generate_vin`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/vin.rb`

## Verification

`PWN::Plugins::VIN.respond_to?(:get_all_manufacturers)` after the
module is loaded. Read the source for parameter names.
