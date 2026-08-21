---
name: pwn-www-uber
description: Drive PWN::WWW::Uber from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Uber
  source: pwn/www/uber.rb
---

# PWN::WWW::Uber

This plugin supports uber.com actions.

## When to use

Call `PWN::WWW::Uber` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/uber.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Uber.help
PWN::WWW::Uber.open(opts)
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

`pwn/www/uber.rb`

## Verification

`PWN::WWW::Uber.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
