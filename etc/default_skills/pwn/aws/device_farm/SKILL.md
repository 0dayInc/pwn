---
name: pwn-aws-devicefarm
description: Drive PWN::AWS::DeviceFarm from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::DeviceFarm
  source: pwn/aws/device_farm.rb
---

# PWN::AWS::DeviceFarm

This module provides a client for making API requests to AWS Device Farm.

## When to use

Call `PWN::AWS::DeviceFarm` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/device_farm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::DeviceFarm.help
PWN::AWS::DeviceFarm.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/device_farm.rb`

## Verification

`PWN::AWS::DeviceFarm.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
