---
name: pwn-aws-simpledb
description: Drive PWN::AWS::SimpleDB from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::SimpleDB
  source: pwn/aws/simple_db.rb
---

# PWN::AWS::SimpleDB

This module provides a client for making API requests to Amazon SimpleDB.

## When to use

Call `PWN::AWS::SimpleDB` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/simple_db.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::SimpleDB.help
PWN::AWS::SimpleDB.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/simple_db.rb`

## Verification

`PWN::AWS::SimpleDB.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
