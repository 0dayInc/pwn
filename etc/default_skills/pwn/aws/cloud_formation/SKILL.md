---
name: pwn-aws-cloudformation
description: Drive PWN::AWS::CloudFormation from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudFormation
  source: pwn/aws/cloud_formation.rb
---

# PWN::AWS::CloudFormation

This module provides a client for making API requests to AWS CloudFormation.

## When to use

Call `PWN::AWS::CloudFormation` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_formation.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudFormation.help
PWN::AWS::CloudFormation.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_formation.rb`

## Verification

`PWN::AWS::CloudFormation.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
