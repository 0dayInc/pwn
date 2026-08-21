---
name: pwn-aws-ecr
description: Drive PWN::AWS::ECR from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ECR
  source: pwn/aws/ecr.rb
---

# PWN::AWS::ECR

This module provides a client for making API requests to Amazon EC2 Container Registry.

## When to use

Call `PWN::AWS::ECR` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/ecr.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ECR.help
PWN::AWS::ECR.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/ecr.rb`

## Verification

`PWN::AWS::ECR.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
