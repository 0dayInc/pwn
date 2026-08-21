---
name: pwn-aws-applicationautoscaling
description: Drive PWN::AWS::ApplicationAutoScaling from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ApplicationAutoScaling
  source: pwn/aws/application_auto_scaling.rb
---

# PWN::AWS::ApplicationAutoScaling

This module provides a client for making API requests to Application Auto Scaling.

## When to use

Call `PWN::AWS::ApplicationAutoScaling` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/application_auto_scaling.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ApplicationAutoScaling.help
PWN::AWS::ApplicationAutoScaling.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/application_auto_scaling.rb`

## Verification

`PWN::AWS::ApplicationAutoScaling.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
