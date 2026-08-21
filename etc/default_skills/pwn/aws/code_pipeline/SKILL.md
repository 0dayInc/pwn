---
name: pwn-aws-codepipeline
description: Drive PWN::AWS::CodePipeline from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CodePipeline
  source: pwn/aws/code_pipeline.rb
---

# PWN::AWS::CodePipeline

This module provides a client for making API requests to AWS CodePipeline.

## When to use

Call `PWN::AWS::CodePipeline` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/code_pipeline.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CodePipeline.help
PWN::AWS::CodePipeline.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/code_pipeline.rb`

## Verification

`PWN::AWS::CodePipeline.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
