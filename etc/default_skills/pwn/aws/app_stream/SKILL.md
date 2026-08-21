---
name: pwn-aws-appstream
description: Drive PWN::AWS::AppStream from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::AppStream
  source: pwn/aws/app_stream.rb
---

# PWN::AWS::AppStream

This module provides a client for making API requests to Amazon AppStream.

## When to use

Call `PWN::AWS::AppStream` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/app_stream.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::AppStream.help
PWN::AWS::AppStream.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/app_stream.rb`

## Verification

`PWN::AWS::AppStream.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
