---
name: pwn-aws-elasticsearchservice
description: Drive PWN::AWS::ElasticsearchService from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ElasticsearchService
  source: pwn/aws/elasticsearch_service.rb
---

# PWN::AWS::ElasticsearchService

This module provides a client for making API requests to Amazon Elasticsearch Service.

## When to use

Call `PWN::AWS::ElasticsearchService` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/elasticsearch_service.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ElasticsearchService.help
PWN::AWS::ElasticsearchService.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/elasticsearch_service.rb`

## Verification

`PWN::AWS::ElasticsearchService.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
