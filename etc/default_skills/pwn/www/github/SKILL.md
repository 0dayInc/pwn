---
name: pwn-www-github
description: Drive PWN::WWW::GitHub from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::GitHub
  source: pwn/www/github.rb
---

# PWN::WWW::GitHub

This plugin supports github.com actions.

## When to use

Call `PWN::WWW::GitHub` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/github.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::GitHub.help
PWN::WWW::GitHub.open(opts)
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

`pwn/www/github.rb`

## Verification

`PWN::WWW::GitHub.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
