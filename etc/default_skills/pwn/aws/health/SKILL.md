---
name: pwn-aws-health
description: Drive PWN::AWS::Health from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Health
  source: pwn/aws/health.rb
---

# PWN::AWS::Health

This module provides a client for making API requests to AWS Health APIs and Notifications.

## When to use

Call `PWN::AWS::Health` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/health.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Health.help
PWN::AWS::Health.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/health.rb`

## Verification

`PWN::AWS::Health.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
