---
name: pwn-plugins-nuclei
description: Drive PWN::Plugins::Nuclei from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Nuclei
  source: pwn/plugins/nuclei.rb
---

# PWN::Plugins::Nuclei

nuclei wrapper: template/severity, JSONL findings.

## When to use

Call `PWN::Plugins::Nuclei` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/nuclei.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Nuclei.help
PWN::Plugins::Nuclei.required_bins(opts)
```

## Public methods

- `required_bins`
- `scan`
- `to_findings`
- `to_defectdojo`
- `authors`
- `help`

## Source

`pwn/plugins/nuclei.rb`

## Verification

`PWN::Plugins::Nuclei.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
