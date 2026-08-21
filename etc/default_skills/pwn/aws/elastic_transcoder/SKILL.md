---
name: pwn-aws-elastictranscoder
description: Drive PWN::AWS::ElasticTranscoder from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::ElasticTranscoder
  source: pwn/aws/elastic_transcoder.rb
---

# PWN::AWS::ElasticTranscoder

This module provides a client for making API requests to Amazon Elastic Transcoder.

## When to use

Call `PWN::AWS::ElasticTranscoder` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/elastic_transcoder.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::ElasticTranscoder.help
PWN::AWS::ElasticTranscoder.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/elastic_transcoder.rb`

## Verification

`PWN::AWS::ElasticTranscoder.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
