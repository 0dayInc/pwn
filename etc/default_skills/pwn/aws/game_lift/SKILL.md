---
name: pwn-aws-gamelift
description: Drive PWN::AWS::GameLift from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::GameLift
  source: pwn/aws/game_lift.rb
---

# PWN::AWS::GameLift

This module provides a client for making API requests to Amazon GameLift.

## When to use

Call `PWN::AWS::GameLift` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/game_lift.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::GameLift.help
PWN::AWS::GameLift.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/game_lift.rb`

## Verification

`PWN::AWS::GameLift.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
