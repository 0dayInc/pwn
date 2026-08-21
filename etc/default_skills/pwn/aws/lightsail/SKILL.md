---
name: pwn-aws-lightsail
description: Drive PWN::AWS::Lightsail from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Lightsail
  source: pwn/aws/lightsail.rb
---

# PWN::AWS::Lightsail

This module provides a client for making API requests to Amazon Lightsail.

## When to use

Call `PWN::AWS::Lightsail` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/lightsail.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Lightsail.help
PWN::AWS::Lightsail.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/lightsail.rb`

## Verification

`PWN::AWS::Lightsail.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
