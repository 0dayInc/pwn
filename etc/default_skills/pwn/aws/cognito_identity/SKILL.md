---
name: pwn-aws-cognitoidentity
description: Drive PWN::AWS::CognitoIdentity from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CognitoIdentity
  source: pwn/aws/cognito_identity.rb
---

# PWN::AWS::CognitoIdentity

This module provides a client for making API requests to Amazon Cognito Identity.

## When to use

Call `PWN::AWS::CognitoIdentity` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cognito_identity.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CognitoIdentity.help
PWN::AWS::CognitoIdentity.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cognito_identity.rb`

## Verification

`PWN::AWS::CognitoIdentity.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
