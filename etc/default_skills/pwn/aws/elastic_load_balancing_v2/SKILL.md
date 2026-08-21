---
name: pwn-aws-elasticloadbalancingv2
description: Drive PWN::AWS::ElasticLoadBalancingV2 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ElasticLoadBalancingV2
  source: pwn/aws/elastic_load_balancing_v2.rb
---

# PWN::AWS::ElasticLoadBalancingV2

This module provides a client for making API requests to Elastic Load Balancing.

## When to use

Call `PWN::AWS::ElasticLoadBalancingV2` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/elastic_load_balancing_v2.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ElasticLoadBalancingV2.help
PWN::AWS::ElasticLoadBalancingV2.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/elastic_load_balancing_v2.rb`

## Verification

`PWN::AWS::ElasticLoadBalancingV2.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
