---
name: pwn-www-pastebin
description: Drive PWN::WWW::Pastebin from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Pastebin
  source: pwn/www/pastebin.rb
---

# PWN::WWW::Pastebin

This plugin supports Pastebin actions.

## When to use

Call `PWN::WWW::Pastebin` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/pastebin.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Pastebin.help
PWN::WWW::Pastebin.open(opts)
```

## Public methods

- `open`
- `onion`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/pastebin.rb`

## Verification

`PWN::WWW::Pastebin.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
