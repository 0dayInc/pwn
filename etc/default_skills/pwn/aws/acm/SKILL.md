---
name: pwn-aws-acm
description: Drive PWN::AWS::ACM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ACM
  source: pwn/aws/acm.rb
---

# PWN::AWS::ACM

This module provides a client for making API requests to AWS Certificate Manager.

## When to use

Call `PWN::AWS::ACM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/acm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ACM.help
PWN::AWS::ACM.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/acm.rb`

## Verification

`PWN::AWS::ACM.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
