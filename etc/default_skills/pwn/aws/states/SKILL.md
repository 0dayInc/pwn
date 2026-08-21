---
name: pwn-aws-states
description: Drive PWN::AWS::States from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::States
  source: pwn/aws/states.rb
---

# PWN::AWS::States

This module provides a client for making API requests to Amazon Elastic Compute Cloud.

## When to use

Call `PWN::AWS::States` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/states.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::States.help
PWN::AWS::States.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/states.rb`

## Verification

`PWN::AWS::States.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
