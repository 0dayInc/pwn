---
name: pwn-aws-batch
description: Drive PWN::AWS::Batch from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Batch
  source: pwn/aws/batch.rb
---

# PWN::AWS::Batch

This module provides a client for making API requests to AWS Batch.

## When to use

Call `PWN::AWS::Batch` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/batch.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Batch.help
PWN::AWS::Batch.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/batch.rb`

## Verification

`PWN::AWS::Batch.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
