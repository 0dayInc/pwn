---
name: pwn-aws-route53
description: Drive PWN::AWS::Route53 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Route53
  source: pwn/aws/route53.rb
---

# PWN::AWS::Route53

This module provides a client for making API requests to Amazon Route 53.

## When to use

Call `PWN::AWS::Route53` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/route53.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Route53.help
PWN::AWS::Route53.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/route53.rb`

## Verification

`PWN::AWS::Route53.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
