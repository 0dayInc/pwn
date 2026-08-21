---
name: pwn-aws-codebuild
description: Drive PWN::AWS::CodeBuild from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CodeBuild
  source: pwn/aws/code_build.rb
---

# PWN::AWS::CodeBuild

This module provides a client for making API requests to AWS CodeBuild.

## When to use

Call `PWN::AWS::CodeBuild` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/code_build.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CodeBuild.help
PWN::AWS::CodeBuild.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/code_build.rb`

## Verification

`PWN::AWS::CodeBuild.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
