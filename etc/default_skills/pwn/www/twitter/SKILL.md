---
name: pwn-www-twitter
description: Drive PWN::WWW::Twitter from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Twitter
  source: pwn/www/twitter.rb
---

# PWN::WWW::Twitter

This plugin supports twitter.com actions.

## When to use

Call `PWN::WWW::Twitter` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/twitter.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Twitter.help
PWN::WWW::Twitter.open(opts)
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

`pwn/www/twitter.rb`

## Verification

`PWN::WWW::Twitter.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
