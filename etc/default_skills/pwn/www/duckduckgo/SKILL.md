---
name: pwn-www-duckduckgo
description: Drive PWN::WWW::Duckduckgo from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Duckduckgo
  source: pwn/www/duckduckgo.rb
---

# PWN::WWW::Duckduckgo

This plugin supports Duckduckgo actions.

## When to use

Call `PWN::WWW::Duckduckgo` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/duckduckgo.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Duckduckgo.help
PWN::WWW::Duckduckgo.open(opts)
```

## Public methods

- `open`
- `search`
- `onion`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/duckduckgo.rb`

## Verification

`PWN::WWW::Duckduckgo.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
