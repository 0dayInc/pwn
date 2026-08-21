---
name: pwn-aws-cognitoidentityprovider
description: Drive PWN::AWS::CognitoIdentityProvider from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AWS::CognitoIdentityProvider
  source: pwn/aws/cognito_identity_provider.rb
---

# PWN::AWS::CognitoIdentityProvider

This module provides a client for making API requests to Amazon Cognito Identity Provider.

## When to use

Call `PWN::AWS::CognitoIdentityProvider` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/aws/cognito_identity_provider.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AWS::CognitoIdentityProvider.help
PWN::AWS::CognitoIdentityProvider.connect(opts)
```

## Public methods

- `connect`
- `disconnect`
- `authors`
- `help`

## Source

`pwn/aws/cognito_identity_provider.rb`

## Verification

`PWN::AWS::CognitoIdentityProvider.respond_to?(:connect)` after the
module is loaded. Read the source for parameter names.
