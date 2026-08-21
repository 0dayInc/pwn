---
name: pwn-aws-opsworks
description: Drive PWN::AWS::OpsWorks from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::OpsWorks
  source: pwn/aws/ops_works.rb
---

# PWN::AWS::OpsWorks

This module provides a client for making API requests to AWS OpsWorks.

## When to use

Call `PWN::AWS::OpsWorks` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/ops_works.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::OpsWorks.help
PWN::AWS::OpsWorks.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/ops_works.rb`

## Verification

`PWN::AWS::OpsWorks.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
