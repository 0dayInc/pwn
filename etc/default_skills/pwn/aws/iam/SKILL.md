---
name: pwn-aws-iam
description: Drive PWN::AWS::IAM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::IAM
  source: pwn/aws/iam.rb
---

# PWN::AWS::IAM

This module provides a client for making API requests to AWS Identity and Access Management.

## When to use

Call `PWN::AWS::IAM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/iam.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::IAM.help
PWN::AWS::IAM.connect(opts)
```

## Public methods

- `connect`
- `decode_key`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/iam.rb`

## Verification

`PWN::AWS::IAM.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
