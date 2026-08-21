---
name: pwn-aws-datapipeline
description: Drive PWN::AWS::DataPipeline from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::DataPipeline
  source: pwn/aws/data_pipleline.rb
---

# PWN::AWS::DataPipeline

This module provides a client for making API requests to AWS Data Pipeline.

## When to use

Call `PWN::AWS::DataPipeline` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/data_pipleline.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::DataPipeline.help
PWN::AWS::DataPipeline.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/data_pipleline.rb`

## Verification

`PWN::AWS::DataPipeline.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
