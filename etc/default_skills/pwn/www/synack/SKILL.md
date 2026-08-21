---
name: pwn-www-synack
description: Drive PWN::WWW::Synack from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Synack
  source: pwn/www/synack.rb
---

# PWN::WWW::Synack

This plugin supports platform.synack.com actions.

## When to use

Call `PWN::WWW::Synack` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/synack.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Synack.help
PWN::WWW::Synack.open(opts)
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

`pwn/www/synack.rb`

## Verification

`PWN::WWW::Synack.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
