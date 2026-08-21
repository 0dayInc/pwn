---
name: pwn-aws-ssm
description: Drive PWN::AWS::SSM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::SSM
  source: pwn/aws/ssm.rb
---

# PWN::AWS::SSM

This module provides a client for making API requests to Amazon Simple Systems Management Service.

## When to use

Call `PWN::AWS::SSM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/ssm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::SSM.help
PWN::AWS::SSM.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/ssm.rb`

## Verification

`PWN::AWS::SSM.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
