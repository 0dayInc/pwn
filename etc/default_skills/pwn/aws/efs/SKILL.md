---
name: pwn-aws-efs
description: Drive PWN::AWS::EFS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::EFS
  source: pwn/aws/efs.rb
---

# PWN::AWS::EFS

This module provides a client for making API requests to Amazon Elastic File System.

## When to use

Call `PWN::AWS::EFS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/efs.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::EFS.help
PWN::AWS::EFS.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/efs.rb`

## Verification

`PWN::AWS::EFS.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
