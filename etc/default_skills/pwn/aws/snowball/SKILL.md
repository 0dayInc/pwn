---
name: pwn-aws-snowball
description: Drive PWN::AWS::Snowball from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Snowball
  source: pwn/aws/snowball.rb
---

# PWN::AWS::Snowball

This module provides a client for making API requests to Amazon Import/Export Snowball.

## When to use

Call `PWN::AWS::Snowball` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/snowball.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Snowball.help
PWN::AWS::Snowball.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/snowball.rb`

## Verification

`PWN::AWS::Snowball.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
