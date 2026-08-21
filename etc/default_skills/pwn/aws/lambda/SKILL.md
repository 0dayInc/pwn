---
name: pwn-aws-lambda
description: Drive PWN::AWS::Lambda from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Lambda
  source: pwn/aws/lambda.rb
---

# PWN::AWS::Lambda

This module provides a client for making API requests to AWS Lambda.

## When to use

Call `PWN::AWS::Lambda` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/lambda.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Lambda.help
PWN::AWS::Lambda.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/lambda.rb`

## Verification

`PWN::AWS::Lambda.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
