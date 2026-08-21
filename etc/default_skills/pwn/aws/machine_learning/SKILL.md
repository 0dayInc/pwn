---
name: pwn-aws-machinelearning
description: Drive PWN::AWS::MachineLearning from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::MachineLearning
  source: pwn/aws/machine_learning.rb
---

# PWN::AWS::MachineLearning

This module provides a client for making API requests to Amazon Machine Learning.

## When to use

Call `PWN::AWS::MachineLearning` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/machine_learning.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::MachineLearning.help
PWN::AWS::MachineLearning.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/machine_learning.rb`

## Verification

`PWN::AWS::MachineLearning.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
