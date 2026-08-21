---
name: pwn-aws-lex
description: Drive PWN::AWS::Lex from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Lex
  source: pwn/aws/lex.rb
---

# PWN::AWS::Lex

This module provides a client for making API requests to Amazon Lex Runtime Service.

## When to use

Call `PWN::AWS::Lex` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/lex.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Lex.help
PWN::AWS::Lex.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/lex.rb`

## Verification

`PWN::AWS::Lex.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
