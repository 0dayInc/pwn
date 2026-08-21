---
name: pwn-www
description: Drive PWN::WWW from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW
  source: pwn/www.rb
---

# PWN::WWW

This file, using the autoload directive loads WWW modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::WWW` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW.help
PWN::WWW.help(opts)
```

## Public methods

- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www.rb`

## Verification

`PWN::WWW.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
