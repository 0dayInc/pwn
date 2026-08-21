---
name: pwn-aws-glacier
description: Drive PWN::AWS::Glacier from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Glacier
  source: pwn/aws/glacier.rb
---

# PWN::AWS::Glacier

This module provides a client for making API requests to Amazon Glacier.

## When to use

Call `PWN::AWS::Glacier` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/glacier.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Glacier.help
PWN::AWS::Glacier.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/glacier.rb`

## Verification

`PWN::AWS::Glacier.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
