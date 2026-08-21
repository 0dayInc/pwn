---
name: pwn-aws-sns
description: Drive PWN::AWS::SNS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::SNS
  source: pwn/aws/sns.rb
---

# PWN::AWS::SNS

This module provides a client for making API requests to Amazon Simple Notification Service.

## When to use

Call `PWN::AWS::SNS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/sns.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::SNS.help
PWN::AWS::SNS.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/sns.rb`

## Verification

`PWN::AWS::SNS.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
