---
name: pwn-aws-elasticloadbalancing
description: Drive PWN::AWS::ElasticLoadBalancing from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ElasticLoadBalancing
  source: pwn/aws/elastic_load_balancing.rb
---

# PWN::AWS::ElasticLoadBalancing

This module provides a client for making API requests to Elastic Load Balancing.

## When to use

Call `PWN::AWS::ElasticLoadBalancing` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/elastic_load_balancing.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ElasticLoadBalancing.help
PWN::AWS::ElasticLoadBalancing.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/elastic_load_balancing.rb`

## Verification

`PWN::AWS::ElasticLoadBalancing.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
