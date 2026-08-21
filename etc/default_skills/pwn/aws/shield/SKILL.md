---
name: pwn-aws-shield
description: Drive PWN::AWS::Shield from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Shield
  source: pwn/aws/shield.rb
---

# PWN::AWS::Shield

This module provides a client for making API requests to AWS Shield.

## When to use

Call `PWN::AWS::Shield` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/shield.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Shield.help
PWN::AWS::Shield.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/shield.rb`

## Verification

`PWN::AWS::Shield.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
