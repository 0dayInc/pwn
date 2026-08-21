---
name: pwn-aws-rekognition
description: Drive PWN::AWS::Rekognition from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Rekognition
  source: pwn/aws/rekognition.rb
---

# PWN::AWS::Rekognition

This module provides a client for making API requests to Amazon Rekognition.

## When to use

Call `PWN::AWS::Rekognition` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/rekognition.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Rekognition.help
PWN::AWS::Rekognition.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/rekognition.rb`

## Verification

`PWN::AWS::Rekognition.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
