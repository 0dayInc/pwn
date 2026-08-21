---
name: pwn-aws-sts
description: Drive PWN::AWS::STS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::STS
  source: pwn/aws/sts.rb
---

# PWN::AWS::STS

This module provides a client for making API requests to AWS Security Token Service.

## When to use

Call `PWN::AWS::STS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/sts.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::STS.help
PWN::AWS::STS.get_temp_credentials(opts)
```

## Public methods

- `get_temp_credentials`
- `authors`
- `help`

## Source

`pwn/aws/sts.rb`

## Verification

`PWN::AWS::STS.respond_to?(:get_temp_credentials)` after the
module is loaded. Read the source for parameter names.
