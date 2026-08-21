---
name: pwn-sdr-frequencyallocation
description: Drive PWN::SDR::FrequencyAllocation from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SDR::FrequencyAllocation
  source: pwn/sdr/frequency_allocation.rb
---

# PWN::SDR::FrequencyAllocation

This moule contains methods for managing frequency allocation band plans

## When to use

Call `PWN::SDR::FrequencyAllocation` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sdr/frequency_allocation.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SDR::FrequencyAllocation.help
PWN::SDR::FrequencyAllocation.band_plans(opts)
```

## Public methods

- `band_plans`
- `authors`
- `help`

## Source

`pwn/sdr/frequency_allocation.rb`

## Verification

`PWN::SDR::FrequencyAllocation.respond_to?(:band_plans)` after the
module is loaded. Read the source for parameter names.
