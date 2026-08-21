---
name: pwn-aws-elasticache
description: Drive PWN::AWS::ElastiCache from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ElastiCache
  source: pwn/aws/elasti_cache.rb
---

# PWN::AWS::ElastiCache

This module provides a client for making API requests to Amazon ElastiCache.

## When to use

Call `PWN::AWS::ElastiCache` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/elasti_cache.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ElastiCache.help
PWN::AWS::ElastiCache.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/elasti_cache.rb`

## Verification

`PWN::AWS::ElastiCache.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
