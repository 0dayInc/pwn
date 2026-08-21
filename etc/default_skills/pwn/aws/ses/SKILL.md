---
name: pwn-aws-ses
description: Drive PWN::AWS::SES from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::SES
  source: pwn/aws/ses.rb
---

# PWN::AWS::SES

This module provides a client for making API requests to Amazon Simple Email Service.

## When to use

Call `PWN::AWS::SES` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/ses.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::SES.help
PWN::AWS::SES.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/ses.rb`

## Verification

`PWN::AWS::SES.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
