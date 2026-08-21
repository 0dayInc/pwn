---
name: pwn-aws-kinesis
description: Drive PWN::AWS::Kinesis from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Kinesis
  source: pwn/aws/kinesis.rb
---

# PWN::AWS::Kinesis

This module provides a client for making API requests to Amazon Kinesis.

## When to use

Call `PWN::AWS::Kinesis` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/kinesis.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Kinesis.help
PWN::AWS::Kinesis.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/kinesis.rb`

## Verification

`PWN::AWS::Kinesis.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
