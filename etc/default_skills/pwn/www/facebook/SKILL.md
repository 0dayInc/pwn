---
name: pwn-www-facebook
description: Drive PWN::WWW::Facebook from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Facebook
  source: pwn/www/facebook.rb
---

# PWN::WWW::Facebook

This plugin supports facebook.com actions.

## When to use

Call `PWN::WWW::Facebook` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/facebook.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Facebook.help
PWN::WWW::Facebook.open(opts)
```

## Public methods

- `open`
- `login`
- `logout`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/facebook.rb`

## Verification

`PWN::WWW::Facebook.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
