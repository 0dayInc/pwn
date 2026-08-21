---
name: pwn-plugins-twitterapi
description: Drive PWN::Plugins::TwitterAPI from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::TwitterAPI
  source: pwn/plugins/twitter_api.rb
---

# PWN::Plugins::TwitterAPI

This plugin converts images to readable text TODO: Convert all rest requests to POST instead of GET

## When to use

Call `PWN::Plugins::TwitterAPI` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/twitter_api.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::TwitterAPI.help
PWN::Plugins::TwitterAPI.app_only_login(opts)
```

## Public methods

- `app_only_login`
- `app_only_logout`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/twitter_api.rb`

## Verification

`PWN::Plugins::TwitterAPI.respond_to?(:app_only_login)` after the
module is loaded. Read the source for parameter names.
