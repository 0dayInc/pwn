---
name: pwn-aws-route53domains
description: Drive PWN::AWS::Route53Domains from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Route53Domains
  source: pwn/aws/route53_domains.rb
---

# PWN::AWS::Route53Domains

This module provides a client for making API requests to Amazon Route 53 Domains.

## When to use

Call `PWN::AWS::Route53Domains` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/route53_domains.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Route53Domains.help
PWN::AWS::Route53Domains.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/route53_domains.rb`

## Verification

`PWN::AWS::Route53Domains.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
