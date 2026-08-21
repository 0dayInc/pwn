---
name: pwn-aws-support
description: Drive PWN::AWS::Support from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Support
  source: pwn/aws/support.rb
---

# PWN::AWS::Support

This module provides a client for making API requests to AWS Support.

## When to use

Call `PWN::AWS::Support` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/support.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Support.help
PWN::AWS::Support.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/support.rb`

## Verification

`PWN::AWS::Support.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
