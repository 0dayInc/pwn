---
name: pwn-aws-xray
description: Drive PWN::AWS::XRay from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::XRay
  source: pwn/aws/x_ray.rb
---

# PWN::AWS::XRay

This module provides a client for making API requests to AWS X-Ray.

## When to use

Call `PWN::AWS::XRay` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/x_ray.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::XRay.help
PWN::AWS::XRay.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/x_ray.rb`

## Verification

`PWN::AWS::XRay.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
