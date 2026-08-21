---
name: pwn-aws-inspector
description: Drive PWN::AWS::Inspector from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Inspector
  source: pwn/aws/inspector.rb
---

# PWN::AWS::Inspector

This module provides a client for making API requests to Amazon Inspector.

## When to use

Call `PWN::AWS::Inspector` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/inspector.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Inspector.help
PWN::AWS::Inspector.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/inspector.rb`

## Verification

`PWN::AWS::Inspector.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
