---
name: pwn-aws-kinesisanalytics
description: Drive PWN::AWS::KinesisAnalytics from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::KinesisAnalytics
  source: pwn/aws/kinesis_analytics.rb
---

# PWN::AWS::KinesisAnalytics

This module provides a client for making API requests to Amazon Kinesis Analytics.

## When to use

Call `PWN::AWS::KinesisAnalytics` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/kinesis_analytics.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::KinesisAnalytics.help
PWN::AWS::KinesisAnalytics.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/kinesis_analytics.rb`

## Verification

`PWN::AWS::KinesisAnalytics.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
