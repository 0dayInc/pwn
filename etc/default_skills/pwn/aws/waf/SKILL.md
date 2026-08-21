---
name: pwn-aws-waf
description: Drive PWN::AWS::WAF from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::WAF
  source: pwn/aws/waf.rb
---

# PWN::AWS::WAF

This module provides a client for making API requests to AWS WAF.

## When to use

Call `PWN::AWS::WAF` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/waf.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::WAF.help
PWN::AWS::WAF.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/waf.rb`

## Verification

`PWN::AWS::WAF.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
