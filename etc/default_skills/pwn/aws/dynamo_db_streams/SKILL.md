---
name: pwn-aws-dynamodbstreams
description: Drive PWN::AWS::DynamoDBStreams from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::DynamoDBStreams
  source: pwn/aws/dynamo_db_streams.rb
---

# PWN::AWS::DynamoDBStreams

This module provides a client for making API requests to Amazon DynamoDB Streams.

## When to use

Call `PWN::AWS::DynamoDBStreams` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/dynamo_db_streams.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::DynamoDBStreams.help
PWN::AWS::DynamoDBStreams.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/dynamo_db_streams.rb`

## Verification

`PWN::AWS::DynamoDBStreams.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
