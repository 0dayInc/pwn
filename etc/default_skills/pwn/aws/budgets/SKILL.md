---
name: pwn-aws-budgets
description: Drive PWN::AWS::Budgets from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Budgets
  source: pwn/aws/budgets.rb
---

# PWN::AWS::Budgets

This module provides a client for making API requests to AWS Budgets.

## When to use

Call `PWN::AWS::Budgets` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/budgets.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Budgets.help
PWN::AWS::Budgets.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/budgets.rb`

## Verification

`PWN::AWS::Budgets.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
