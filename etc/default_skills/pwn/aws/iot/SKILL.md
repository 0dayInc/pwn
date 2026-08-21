---
name: pwn-aws-iot
description: Drive PWN::AWS::IoT from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::IoT
  source: pwn/aws/iot.rb
---

# PWN::AWS::IoT

This module provides a client for making API requests to AWS IoT.

## When to use

Call `PWN::AWS::IoT` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/iot.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::IoT.help
PWN::AWS::IoT.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/iot.rb`

## Verification

`PWN::AWS::IoT.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
