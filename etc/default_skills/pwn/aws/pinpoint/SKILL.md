---
name: pwn-aws-pinpoint
description: Drive PWN::AWS::Pinpoint from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Pinpoint
  source: pwn/aws/pinpoint.rb
---

# PWN::AWS::Pinpoint

This module provides a client for making API requests to Amazon Elastic Compute Cloud.

## When to use

Call `PWN::AWS::Pinpoint` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/pinpoint.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Pinpoint.help
PWN::AWS::Pinpoint.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/pinpoint.rb`

## Verification

`PWN::AWS::Pinpoint.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
