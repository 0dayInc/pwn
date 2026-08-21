---
name: pwn-aws-opsworkscm
description: Drive PWN::AWS::OpsWorksCM from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::OpsWorksCM
  source: pwn/aws/ops_works_cm.rb
---

# PWN::AWS::OpsWorksCM

This module provides a client for making API requests to AWS OpsWorks for Chef Automate.

## When to use

Call `PWN::AWS::OpsWorksCM` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/ops_works_cm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::OpsWorksCM.help
PWN::AWS::OpsWorksCM.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/ops_works_cm.rb`

## Verification

`PWN::AWS::OpsWorksCM.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
