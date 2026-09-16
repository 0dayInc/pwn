---
name: pwn-plugins-sbom
description: Drive PWN::Plugins::SBOM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::SBOM
  source: pwn/plugins/sbom.rb
---

# PWN::Plugins::SBOM

Generic lockfile/image CVE scan with engine selection.

## When to use

Call `PWN::Plugins::SBOM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/sbom.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::SBOM.help
PWN::Plugins::SBOM.required_bins(opts)
```

## Public methods

- `required_bins`
- `scan`
- `authors`
- `help`

## Source

`pwn/plugins/sbom.rb`

## Verification

`PWN::Plugins::SBOM.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
