---
name: pwn-plugins-semgrep
description: Drive PWN::Plugins::Semgrep from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Semgrep
  source: pwn/plugins/semgrep.rb
---

# PWN::Plugins::Semgrep

semgrep wrapper feeding SAST-shaped findings.

## When to use

Call `PWN::Plugins::Semgrep` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/semgrep.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Semgrep.help
PWN::Plugins::Semgrep.required_bins(opts)
```

## Public methods

- `required_bins`
- `scan`
- `authors`
- `help`

## Source

`pwn/plugins/semgrep.rb`

## Verification

`PWN::Plugins::Semgrep.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
