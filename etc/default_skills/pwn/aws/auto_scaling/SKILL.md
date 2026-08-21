---
name: pwn-aws-autoscaling
description: Drive PWN::AWS::AutoScaling from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::AutoScaling
  source: pwn/aws/auto_scaling.rb
---

# PWN::AWS::AutoScaling

This module provides a client for making API requests to Auto Scaling.

## When to use

Call `PWN::AWS::AutoScaling` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/auto_scaling.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::AutoScaling.help
PWN::AWS::AutoScaling.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/auto_scaling.rb`

## Verification

`PWN::AWS::AutoScaling.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
