---
name: pwn-aws-apigateway
description: Drive PWN::AWS::APIGateway from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::APIGateway
  source: pwn/aws/api_gateway.rb
---

# PWN::AWS::APIGateway

This module provides a client for making API requests to Amazon API Gateway.

## When to use

Call `PWN::AWS::APIGateway` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/api_gateway.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::APIGateway.help
PWN::AWS::APIGateway.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/api_gateway.rb`

## Verification

`PWN::AWS::APIGateway.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
