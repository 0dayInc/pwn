---
name: pwn-aws-workspaces
description: Drive PWN::AWS::Workspaces from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::Workspaces
  source: pwn/aws/workspaces.rb
---

# PWN::AWS::Workspaces

This module provides a client for making API requests to Amazon WorkSpaces.

## When to use

Call `PWN::AWS::Workspaces` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/workspaces.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::Workspaces.help
PWN::AWS::Workspaces.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/workspaces.rb`

## Verification

`PWN::AWS::Workspaces.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
