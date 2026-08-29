---
name: pwn-plugins-doctor
description: Drive PWN::Plugins::Doctor from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Doctor
  source: pwn/plugins/doctor.rb
---

# PWN::Plugins::Doctor

Plugin/binary/capability preflight. Plugins declare required_bins / required_caps; HOST summaries list degraded modules without autoloading the whole plugin tree.

## When to use

Call `PWN::Plugins::Doctor` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/doctor.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Doctor.help
PWN::Plugins::Doctor.required_bins(opts)
```

## Public methods

- `required_bins`
- `bin`
- `require_bin`
- `cap_net_raw`
- `require_cap_net_raw`
- `check`
- `host_summary`
- `authors`
- `help`
- `bin?`
- `cap_net_raw?`
- `require_bin!`
- `require_cap_net_raw!`

## Source

`pwn/plugins/doctor.rb`

## Verification

`PWN::Plugins::Doctor.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
