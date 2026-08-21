---
name: pwn-aws-elasticbeanstalk
description: Drive PWN::AWS::ElasticBeanstalk from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ElasticBeanstalk
  source: pwn/aws/elastic_beanstalk.rb
---

# PWN::AWS::ElasticBeanstalk

This module provides a client for making API requests to AWS Elastic Beanstalk.

## When to use

Call `PWN::AWS::ElasticBeanstalk` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/elastic_beanstalk.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ElasticBeanstalk.help
PWN::AWS::ElasticBeanstalk.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/elastic_beanstalk.rb`

## Verification

`PWN::AWS::ElasticBeanstalk.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
