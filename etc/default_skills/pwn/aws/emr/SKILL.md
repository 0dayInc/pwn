---
name: pwn-aws-emr
description: Drive PWN::AWS::EMR from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::EMR
  source: pwn/aws/emr.rb
---

# PWN::AWS::EMR

This module provides a client for making API requests to Amazon Elastic MapReduce.

## When to use

Call `PWN::AWS::EMR` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/emr.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::EMR.help
PWN::AWS::EMR.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/emr.rb`

## Verification

`PWN::AWS::EMR.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
