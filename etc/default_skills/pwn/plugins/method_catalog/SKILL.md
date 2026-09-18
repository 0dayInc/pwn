---
name: pwn-plugins-methodcatalog
description: Drive PWN::Plugins::MethodCatalog from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::MethodCatalog
  source: pwn/plugins/method_catalog.rb
---

# PWN::Plugins::MethodCatalog

JSON-schema descriptors for public PWN::Plugins methods, generated from YARD / Supported Method Parameters docs. pwn_eval validates kwargs first.

## When to use

Call `PWN::Plugins::MethodCatalog` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/method_catalog.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::MethodCatalog.help
PWN::Plugins::MethodCatalog.required_bins(opts)
```

## Public methods

- `required_bins`
- `schema`
- `guard_eval`
- `descriptors`
- `authors`
- `help`

## Source

`pwn/plugins/method_catalog.rb`

## Verification

`PWN::Plugins::MethodCatalog.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
