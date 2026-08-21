---
name: pwn-aws-ecs
description: Drive PWN::AWS::ECS from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ECS
  source: pwn/aws/ecs.rb
---

# PWN::AWS::ECS

This module provides a client for making API requests to Amazon EC2 Container Service.

## When to use

Call `PWN::AWS::ECS` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/ecs.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ECS.help
PWN::AWS::ECS.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/ecs.rb`

## Verification

`PWN::AWS::ECS.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
