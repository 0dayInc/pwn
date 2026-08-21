---
name: pwn-aws-firehose
description: Drive PWN::AWS::Firehose from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Firehose
  source: pwn/aws/firehose.rb
---

# PWN::AWS::Firehose

This module provides a client for making API requests to Amazon Kinesis Firehose.

## When to use

Call `PWN::AWS::Firehose` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/firehose.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Firehose.help
PWN::AWS::Firehose.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/firehose.rb`

## Verification

`PWN::AWS::Firehose.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
