---
name: pwn-reports-xml
description: Drive PWN::Reports::XML from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Reports::XML
  source: pwn/reports/xml.rb
---

# PWN::Reports::XML

Generic XML report writer for pentest / findings payloads.

## When to use

Call `PWN::Reports::XML` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/reports/xml.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Reports::XML.help
PWN::Reports::XML.generate(opts)
```

## Public methods

- `generate`
- `authors`
- `help`

## Source

`pwn/reports/xml.rb`

## Verification

`PWN::Reports::XML.respond_to?(:generate)` after the
module is loaded. Read the source for parameter names.
