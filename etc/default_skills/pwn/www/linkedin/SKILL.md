---
name: pwn-www-linkedin
description: Drive PWN::WWW::Linkedin from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Linkedin
  source: pwn/www/linkedin.rb
---

# PWN::WWW::Linkedin

This plugin supports linkedin.com actions.

## When to use

Call `PWN::WWW::Linkedin` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/linkedin.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Linkedin.help
PWN::WWW::Linkedin.open(opts)
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

`pwn/www/linkedin.rb`

## Verification

`PWN::WWW::Linkedin.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
