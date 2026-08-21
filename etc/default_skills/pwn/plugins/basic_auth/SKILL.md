---
name: pwn-plugins-basicauth
description: Drive PWN::Plugins::BasicAuth from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BasicAuth
  source: pwn/plugins/basic_auth.rb
---

# PWN::Plugins::BasicAuth

This plugin Base64 encodes/decodes AuthN credentials for passing to a ''Basic'' authorization HTTP header.

## When to use

Call `PWN::Plugins::BasicAuth` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/basic_auth.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BasicAuth.help
PWN::Plugins::BasicAuth.encode(opts)
```

## Public methods

- `encode`
- `decode`
- `authors`
- `help`

## Source

`pwn/plugins/basic_auth.rb`

## Verification

`PWN::Plugins::BasicAuth.respond_to?(:encode)` after the
module is loaded. Read the source for parameter names.
