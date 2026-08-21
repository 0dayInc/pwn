---
name: pwn-aws-sqs
description: Drive PWN::AWS::SQS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::SQS
  source: pwn/aws/sqs.rb
---

# PWN::AWS::SQS

This module provides a client for making API requests to Amazon Simple Queue Service.

## When to use

Call `PWN::AWS::SQS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/sqs.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::SQS.help
PWN::AWS::SQS.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/sqs.rb`

## Verification

`PWN::AWS::SQS.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
