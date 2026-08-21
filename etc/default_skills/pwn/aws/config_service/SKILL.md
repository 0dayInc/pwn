---
name: pwn-aws-configservice
description: Drive PWN::AWS::ConfigService from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ConfigService
  source: pwn/aws/config_service.rb
---

# PWN::AWS::ConfigService

This module provides a client for making API requests to AWS Config.

## When to use

Call `PWN::AWS::ConfigService` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/config_service.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ConfigService.help
PWN::AWS::ConfigService.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/config_service.rb`

## Verification

`PWN::AWS::ConfigService.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
