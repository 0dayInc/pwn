---
name: pwn-aws-ec2
description: Drive PWN::AWS::EC2 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::EC2
  source: pwn/aws/ec2.rb
---

# PWN::AWS::EC2

This module provides a client for making API requests to Amazon Elastic Compute Cloud.

## When to use

Call `PWN::AWS::EC2` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/ec2.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::EC2.help
PWN::AWS::EC2.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/ec2.rb`

## Verification

`PWN::AWS::EC2.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
