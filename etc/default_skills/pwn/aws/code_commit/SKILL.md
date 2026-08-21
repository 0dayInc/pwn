---
name: pwn-aws-codecommit
description: Drive PWN::AWS::CodeCommit from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CodeCommit
  source: pwn/aws/code_commit.rb
---

# PWN::AWS::CodeCommit

This module provides a client for making API requests to AWS CodeCommit.

## When to use

Call `PWN::AWS::CodeCommit` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/code_commit.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CodeCommit.help
PWN::AWS::CodeCommit.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/code_commit.rb`

## Verification

`PWN::AWS::CodeCommit.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
