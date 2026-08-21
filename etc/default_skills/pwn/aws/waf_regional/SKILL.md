---
name: pwn-aws-wafregional
description: Drive PWN::AWS::WAFRegional from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::WAFRegional
  source: pwn/aws/waf_regional.rb
---

# PWN::AWS::WAFRegional

This module provides a client for making API requests to AWS WAF Regional.

## When to use

Call `PWN::AWS::WAFRegional` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/waf_regional.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::WAFRegional.help
PWN::AWS::WAFRegional.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/waf_regional.rb`

## Verification

`PWN::AWS::WAFRegional.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
