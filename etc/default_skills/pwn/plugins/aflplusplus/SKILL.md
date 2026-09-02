---
name: pwn-plugins-aflplusplus
description: Drive PWN::Plugins::AFLplusplus from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::AFLplusplus
  source: pwn/plugins/aflplusplus.rb
---

# PWN::Plugins::AFLplusplus

AFL++ campaign wrapper.

## When to use

Call `PWN::Plugins::AFLplusplus` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/aflplusplus.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::AFLplusplus.help
PWN::Plugins::AFLplusplus.required_bins(opts)
```

## Public methods

- `required_bins`
- `fuzz`
- `parse_stats`
- `crash_triage`
- `minimize`
- `authors`
- `help`

## Source

`pwn/plugins/aflplusplus.rb`

## Verification

`PWN::Plugins::AFLplusplus.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
