---
name: pwn-www-bing
description: Drive PWN::WWW::Bing from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Bing
  source: pwn/www/bing.rb
---

# PWN::WWW::Bing

This plugin supports Bing actions.

## When to use

Call `PWN::WWW::Bing` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/bing.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Bing.help
PWN::WWW::Bing.open(opts)
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

`pwn/www/bing.rb`

## Verification

`PWN::WWW::Bing.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
