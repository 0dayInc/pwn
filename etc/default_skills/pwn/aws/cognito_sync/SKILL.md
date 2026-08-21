---
name: pwn-aws-cognitosync
description: Drive PWN::AWS::CognitoSync from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CognitoSync
  source: pwn/aws/cognito_sync.rb
---

# PWN::AWS::CognitoSync

This module provides a client for making API requests to Amazon Cognito Sync.

## When to use

Call `PWN::AWS::CognitoSync` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cognito_sync.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CognitoSync.help
PWN::AWS::CognitoSync.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cognito_sync.rb`

## Verification

`PWN::AWS::CognitoSync.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
