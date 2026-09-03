---
name: pwn-plugins-findings
description: Drive PWN::Plugins::Findings from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Findings
  source: pwn/plugins/findings.rb
---

# PWN::Plugins::Findings

Persistent finding rows for pwn-ai (title, severity, host, evidence, PoC).

## When to use

Call `PWN::Plugins::Findings` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/findings.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Findings.help
PWN::Plugins::Findings.required_bins(opts)
```

## Public methods

- `required_bins`
- `record`
- `evidence_verify`
- `report`
- `query`
- `chain`
- `render`
- `authors`
- `help`

## Source

`pwn/plugins/findings.rb`

## Verification

`PWN::Plugins::Findings.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
