---
name: pwn-aws-cloudwatch
description: Drive PWN::AWS::CloudWatch from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudWatch
  source: pwn/aws/cloud_watch.rb
---

# PWN::AWS::CloudWatch

This module provides a client for making API requests to Amazon CloudWatch.

## When to use

Call `PWN::AWS::CloudWatch` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_watch.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudWatch.help
PWN::AWS::CloudWatch.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_watch.rb`

## Verification

`PWN::AWS::CloudWatch.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
