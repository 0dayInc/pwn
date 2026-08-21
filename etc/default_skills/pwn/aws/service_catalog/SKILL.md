---
name: pwn-aws-servicecatalog
description: Drive PWN::AWS::ServiceCatalog from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ServiceCatalog
  source: pwn/aws/service_catalog.rb
---

# PWN::AWS::ServiceCatalog

This module provides a client for making API requests to AWS Service Catalog.

## When to use

Call `PWN::AWS::ServiceCatalog` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/service_catalog.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ServiceCatalog.help
PWN::AWS::ServiceCatalog.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/service_catalog.rb`

## Verification

`PWN::AWS::ServiceCatalog.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
