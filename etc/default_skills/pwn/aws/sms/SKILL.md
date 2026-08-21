---
name: pwn-aws-sms
description: Drive PWN::AWS::SMS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::SMS
  source: pwn/aws/sms.rb
---

# PWN::AWS::SMS

This module provides a client for making API requests to AWS Server Migration Service.

## When to use

Call `PWN::AWS::SMS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/sms.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::SMS.help
PWN::AWS::SMS.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/sms.rb`

## Verification

`PWN::AWS::SMS.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
