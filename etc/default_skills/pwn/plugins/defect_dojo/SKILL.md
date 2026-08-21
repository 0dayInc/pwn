---
name: pwn-plugins-defectdojo
description: Drive PWN::Plugins::DefectDojo from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::DefectDojo
  source: pwn/plugins/defect_dojo.rb
---

# PWN::Plugins::DefectDojo

This plugin converts images to readable text TODO: Convert all rest requests to POST instead of GET

## When to use

Call `PWN::Plugins::DefectDojo` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/defect_dojo.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::DefectDojo.help
PWN::Plugins::DefectDojo.login(opts)
```

## Public methods

- `login`
- `product_list`
- `engagement_list`
- `engagement_create`
- `test_list`
- `importscan`
- `reimportscan`
- `finding_list`
- `user_list`
- `tool_configuration_list`
- `logout`
- `authors`
- `help`

## Source

`pwn/plugins/defect_dojo.rb`

## Verification

`PWN::Plugins::DefectDojo.respond_to?(:login)` after the
module is loaded. Read the source for parameter names.
