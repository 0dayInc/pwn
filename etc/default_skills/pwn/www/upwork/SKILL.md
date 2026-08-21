---
name: pwn-www-upwork
description: Drive PWN::WWW::Upwork from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Upwork
  source: pwn/www/upwork.rb
---

# PWN::WWW::Upwork

This plugin supports pandora.com actions.

## When to use

Call `PWN::WWW::Upwork` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/upwork.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Upwork.help
PWN::WWW::Upwork.open(opts)
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

`pwn/www/upwork.rb`

## Verification

`PWN::WWW::Upwork.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
