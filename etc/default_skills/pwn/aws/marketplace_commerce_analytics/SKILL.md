---
name: pwn-aws-marketplacecommerceanalytics
description: Drive PWN::AWS::MarketplaceCommerceAnalytics from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::MarketplaceCommerceAnalytics
  source: pwn/aws/marketplace_commerce_analytics.rb
---

# PWN::AWS::MarketplaceCommerceAnalytics

This module provides a client for making API requests to AWS Marketplace Commerce Analytics.

## When to use

Call `PWN::AWS::MarketplaceCommerceAnalytics` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/marketplace_commerce_analytics.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::MarketplaceCommerceAnalytics.help
PWN::AWS::MarketplaceCommerceAnalytics.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/marketplace_commerce_analytics.rb`

## Verification

`PWN::AWS::MarketplaceCommerceAnalytics.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
