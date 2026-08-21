---
name: pwn-www-checkip
description: Drive PWN::WWW::Checkip from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Checkip
  source: pwn/www/checkip.rb
---

# PWN::WWW::Checkip

This plugin supports Checkip actions.

## When to use

Call `PWN::WWW::Checkip` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/checkip.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Checkip.help
PWN::WWW::Checkip.open(opts)
```

## Public methods

- `open`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/checkip.rb`

## Verification

`PWN::WWW::Checkip.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
