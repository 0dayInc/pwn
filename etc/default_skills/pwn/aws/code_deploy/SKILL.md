---
name: pwn-aws-codedeploy
description: Drive PWN::AWS::CodeDeploy from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CodeDeploy
  source: pwn/aws/code_deploy.rb
---

# PWN::AWS::CodeDeploy

This module provides a client for making API requests to AWS CodeDeploy.

## When to use

Call `PWN::AWS::CodeDeploy` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/code_deploy.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CodeDeploy.help
PWN::AWS::CodeDeploy.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/code_deploy.rb`

## Verification

`PWN::AWS::CodeDeploy.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
