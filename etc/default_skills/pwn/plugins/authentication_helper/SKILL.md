---
name: pwn-plugins-authenticationhelper
description: Drive PWN::Plugins::AuthenticationHelper from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::AuthenticationHelper
  source: pwn/plugins/authentication_helper.rb
---

# PWN::Plugins::AuthenticationHelper

This plugin is used to assist in masking a password when entered in via STDIN to prevent would-be shoulder surfers from obtaining password information. This plugin is useful when demonstrating the functionality of other SP plugins/modules.

## When to use

Call `PWN::Plugins::AuthenticationHelper` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/authentication_helper.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::AuthenticationHelper.help
PWN::Plugins::AuthenticationHelper.username(opts)
```

## Public methods

- `username`
- `mask_password`
- `mfa`
- `authors`
- `help`

## Source

`pwn/plugins/authentication_helper.rb`

## Verification

`PWN::Plugins::AuthenticationHelper.respond_to?(:username)` after the
module is loaded. Read the source for parameter names.
