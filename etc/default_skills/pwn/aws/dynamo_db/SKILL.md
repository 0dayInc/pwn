---
name: pwn-aws-dynamodb
description: Drive PWN::AWS::DynamoDB from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::DynamoDB
  source: pwn/aws/dynamo_db.rb
---

# PWN::AWS::DynamoDB

This module provides a client for making API requests to Amazon DynamoDB.

## When to use

Call `PWN::AWS::DynamoDB` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/dynamo_db.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::DynamoDB.help
PWN::AWS::DynamoDB.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/dynamo_db.rb`

## Verification

`PWN::AWS::DynamoDB.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
