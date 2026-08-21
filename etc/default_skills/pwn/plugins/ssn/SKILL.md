---
name: pwn-plugins-ssn
description: Drive PWN::Plugins::SSN from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::SSN
  source: pwn/plugins/ssn.rb
---

# PWN::Plugins::SSN

This plugin provides useful social security number capabilities

## When to use

Call `PWN::Plugins::SSN` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/ssn.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::SSN.help
PWN::Plugins::SSN.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/ssn.rb`

## Verification

`PWN::Plugins::SSN.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
