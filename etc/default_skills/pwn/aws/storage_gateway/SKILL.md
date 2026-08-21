---
name: pwn-aws-storagegateway
description: Drive PWN::AWS::StorageGateway from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::StorageGateway
  source: pwn/aws/storage_gateway.rb
---

# PWN::AWS::StorageGateway

This module provides a client for making API requests to AWS Storage Gateway.

## When to use

Call `PWN::AWS::StorageGateway` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/storage_gateway.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::StorageGateway.help
PWN::AWS::StorageGateway.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/storage_gateway.rb`

## Verification

`PWN::AWS::StorageGateway.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
