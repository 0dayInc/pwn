---
name: pwn-aws-kms
description: Drive PWN::AWS::KMS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::KMS
  source: pwn/aws/kms.rb
---

# PWN::AWS::KMS

This module provides a client for making API requests to AWS Key Management Service.

## When to use

Call `PWN::AWS::KMS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/kms.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::KMS.help
PWN::AWS::KMS.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/kms.rb`

## Verification

`PWN::AWS::KMS.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
