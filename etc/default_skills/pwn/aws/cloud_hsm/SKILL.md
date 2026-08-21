---
name: pwn-aws-cloudhsm
description: Drive PWN::AWS::CloudHSM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudHSM
  source: pwn/aws/cloud_hsm.rb
---

# PWN::AWS::CloudHSM

This module provides a client for making API requests to Amazon CloudHSM.

## When to use

Call `PWN::AWS::CloudHSM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_hsm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudHSM.help
PWN::AWS::CloudHSM.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_hsm.rb`

## Verification

`PWN::AWS::CloudHSM.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
