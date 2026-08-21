---
name: pwn-aws-cloudsearchdomain
description: Drive PWN::AWS::CloudSearchDomain from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CloudSearchDomain
  source: pwn/aws/cloud_search_domain.rb
---

# PWN::AWS::CloudSearchDomain

Returns a client suitable for making requests against a CloudSearch domain.

## When to use

Call `PWN::AWS::CloudSearchDomain` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cloud_search_domain.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CloudSearchDomain.help
PWN::AWS::CloudSearchDomain.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cloud_search_domain.rb`

## Verification

`PWN::AWS::CloudSearchDomain.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
