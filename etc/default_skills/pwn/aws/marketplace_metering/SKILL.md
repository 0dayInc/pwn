---
name: pwn-aws-marketplacemetering
description: Drive PWN::AWS::MarketplaceMetering from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::MarketplaceMetering
  source: pwn/aws/marketplace_metering.rb
---

# PWN::AWS::MarketplaceMetering

This module provides a client for making API requests to AWSMarketplace Metering.

## When to use

Call `PWN::AWS::MarketplaceMetering` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/marketplace_metering.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::MarketplaceMetering.help
PWN::AWS::MarketplaceMetering.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/marketplace_metering.rb`

## Verification

`PWN::AWS::MarketplaceMetering.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
