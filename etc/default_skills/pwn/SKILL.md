---
name: pwn
description: Drive PWN from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN
  source: pwn.rb
---

# PWN

Thank you for choosing the Continuous Security Integrtion Framework! Your Source for Source Code Analysis, Vulnerability Scanning, Exploitation, & General Security Testing in a Continuous Integration Environment

## When to use

Call `PWN` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN.help
PWN.help(opts)
```

## Public methods

- `help`

## Source

`pwn.rb`

## Verification

`PWN.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
