---
name: pwn-aws-cloudfront
description: Drive PWN::AWS::CloudFront from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudFront
  source: pwn/aws/cloud_front.rb
---

# PWN::AWS::CloudFront

This module provides a client for making API requests to Amazon CloudFront.

## When to use

Call `PWN::AWS::CloudFront` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_front.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudFront.help
PWN::AWS::CloudFront.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_front.rb`

## Verification

`PWN::AWS::CloudFront.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
