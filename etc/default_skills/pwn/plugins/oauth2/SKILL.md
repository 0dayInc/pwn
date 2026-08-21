---
name: pwn-plugins-oauth2
description: Drive PWN::Plugins::OAuth2 from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::OAuth2
  source: pwn/plugins/oauth2.rb
---

# PWN::Plugins::OAuth2

This plugin is somewhat of a hack used for extracting OAuth2 tokens from HTTP responses to be used for subsequent HTTP requests.

## When to use

Call `PWN::Plugins::OAuth2` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/oauth2.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::OAuth2.help
PWN::Plugins::OAuth2.decode(opts)
```

## Public methods

- `decode`
- `get_value_by_key`
- `authors`
- `help`

## Source

`pwn/plugins/oauth2.rb`

## Verification

`PWN::Plugins::OAuth2.respond_to?(:decode)` after the
module is loaded. Read the source for parameter names.
