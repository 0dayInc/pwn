---
name: pwn-aws-directconnect
description: Drive PWN::AWS::DirectConnect from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::DirectConnect
  source: pwn/aws/direct_connect.rb
---

# PWN::AWS::DirectConnect

This module provides a client for making API requests to AWS Direct Connect.

## When to use

Call `PWN::AWS::DirectConnect` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/direct_connect.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::DirectConnect.help
PWN::AWS::DirectConnect.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/direct_connect.rb`

## Verification

`PWN::AWS::DirectConnect.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
