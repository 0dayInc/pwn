---
name: pwn-aws-cloudtrail
description: Drive PWN::AWS::CloudTrail from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudTrail
  source: pwn/aws/cloud_trail.rb
---

# PWN::AWS::CloudTrail

This module provides a client for making API requests to AWS CloudTrail.

## When to use

Call `PWN::AWS::CloudTrail` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_trail.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudTrail.help
PWN::AWS::CloudTrail.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_trail.rb`

## Verification

`PWN::AWS::CloudTrail.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
