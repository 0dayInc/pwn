---
name: pwn-aws-s3
description: Drive PWN::AWS::S3 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::S3
  source: pwn/aws/s3.rb
---

# PWN::AWS::S3

This module provides a client for making API requests to Amazon Simple Storage Service.

## When to use

Call `PWN::AWS::S3` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/s3.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::S3.help
PWN::AWS::S3.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/s3.rb`

## Verification

`PWN::AWS::S3.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
