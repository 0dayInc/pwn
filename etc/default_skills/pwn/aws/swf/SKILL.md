---
name: pwn-aws-swf
description: Drive PWN::AWS::SWF from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::SWF
  source: pwn/aws/swf.rb
---

# PWN::AWS::SWF

This module provides a client for making API requests to Amazon Simple Workflow Service.

## When to use

Call `PWN::AWS::SWF` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/swf.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::SWF.help
PWN::AWS::SWF.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/swf.rb`

## Verification

`PWN::AWS::SWF.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
