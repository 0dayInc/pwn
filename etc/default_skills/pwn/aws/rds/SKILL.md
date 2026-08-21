---
name: pwn-aws-rds
description: Drive PWN::AWS::RDS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::RDS
  source: pwn/aws/rds.rb
---

# PWN::AWS::RDS

This module provides a client for making API requests to Amazon Relational Database Service.

## When to use

Call `PWN::AWS::RDS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/rds.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::RDS.help
PWN::AWS::RDS.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/rds.rb`

## Verification

`PWN::AWS::RDS.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
