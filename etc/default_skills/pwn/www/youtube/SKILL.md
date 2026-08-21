---
name: pwn-www-youtube
description: Drive PWN::WWW::Youtube from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Youtube
  source: pwn/www/youtube.rb
---

# PWN::WWW::Youtube

This plugin supports Youtube actions.

## When to use

Call `PWN::WWW::Youtube` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/youtube.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Youtube.help
PWN::WWW::Youtube.open(opts)
```

## Public methods

- `open`
- `search`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/youtube.rb`

## Verification

`PWN::WWW::Youtube.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
