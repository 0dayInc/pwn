---
name: pwn-aws-importexport
description: Drive PWN::AWS::ImportExport from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ImportExport
  source: pwn/aws/import_export.rb
---

# PWN::AWS::ImportExport

This module provides a client for making API requests to AWS Import/Export.

## When to use

Call `PWN::AWS::ImportExport` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/import_export.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ImportExport.help
PWN::AWS::ImportExport.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/import_export.rb`

## Verification

`PWN::AWS::ImportExport.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
