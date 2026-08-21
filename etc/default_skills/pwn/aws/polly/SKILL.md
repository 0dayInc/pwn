---
name: pwn-aws-polly
description: Drive PWN::AWS::Polly from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Polly
  source: pwn/aws/polly.rb
---

# PWN::AWS::Polly

This module provides a client for making API requests to Amazon Polly.

## When to use

Call `PWN::AWS::Polly` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/polly.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Polly.help
PWN::AWS::Polly.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/polly.rb`

## Verification

`PWN::AWS::Polly.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
