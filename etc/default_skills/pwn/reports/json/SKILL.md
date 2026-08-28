---
name: pwn-reports-json
description: Drive PWN::Reports::JSON from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::JSON
  source: pwn/reports/json.rb
---

# PWN::Reports::JSON

Generic JSON report writer for pentest / findings payloads.

## When to use

Call `PWN::Reports::JSON` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/json.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::JSON.help
PWN::Reports::JSON.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/reports/json.rb`

## Verification

`PWN::Reports::JSON.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
