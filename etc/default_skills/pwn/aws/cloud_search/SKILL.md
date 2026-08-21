---
name: pwn-aws-cloudsearch
description: Drive PWN::AWS::CloudSearch from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudSearch
  source: pwn/aws/cloud_search.rb
---

# PWN::AWS::CloudSearch

This module provides a client for making API requests to Amazon CloudSearch.

## When to use

Call `PWN::AWS::CloudSearch` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_search.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudSearch.help
PWN::AWS::CloudSearch.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_search.rb`

## Verification

`PWN::AWS::CloudSearch.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
