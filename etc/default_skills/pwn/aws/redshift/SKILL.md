---
name: pwn-aws-redshift
description: Drive PWN::AWS::Redshift from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Redshift
  source: pwn/aws/redshift.rb
---

# PWN::AWS::Redshift

This module provides a client for making API requests to Amazon Redshift.

## When to use

Call `PWN::AWS::Redshift` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/redshift.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Redshift.help
PWN::AWS::Redshift.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/redshift.rb`

## Verification

`PWN::AWS::Redshift.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
