---
name: pwn-aws-lambdapreview
description: Drive PWN::AWS::LambdaPreview from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::LambdaPreview
  source: pwn/aws/lambda_preview.rb
---

# PWN::AWS::LambdaPreview

This module provides a client for making API requests to AWS Lambda.

## When to use

Call `PWN::AWS::LambdaPreview` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/lambda_preview.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::LambdaPreview.help
PWN::AWS::LambdaPreview.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/lambda_preview.rb`

## Verification

`PWN::AWS::LambdaPreview.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
