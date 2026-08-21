---
name: pwn-www-pandora
description: Drive PWN::WWW::Pandora from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Pandora
  source: pwn/www/pandora.rb
---

# PWN::WWW::Pandora

This plugin supports pandora.com actions.

## When to use

Call `PWN::WWW::Pandora` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/pandora.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Pandora.help
PWN::WWW::Pandora.open(opts)
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

`pwn/www/pandora.rb`

## Verification

`PWN::WWW::Pandora.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
