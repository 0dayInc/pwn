---
name: pwn-plugins-volatility
description: Drive PWN::Plugins::Volatility from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Volatility
  source: pwn/plugins/volatility.rb
---

# PWN::Plugins::Volatility

volatility3 wrapper.

## When to use

Call `PWN::Plugins::Volatility` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/volatility.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Volatility.help
PWN::Plugins::Volatility.required_bins(opts)
```

## Public methods

- `required_bins`
- `run`
- `yara`
- `authors`
- `help`

## Source

`pwn/plugins/volatility.rb`

## Verification

`PWN::Plugins::Volatility.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
