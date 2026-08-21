---
name: pwn-banner
description: Drive PWN::Banner from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Banner
  source: pwn/banner.rb
---

# PWN::Banner

This file, using the autoload directive loads Banner modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::Banner` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/banner.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Banner.help
PWN::Banner.get(opts)
```

## Public methods

- `get`
- `welcome`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/banner.rb`

## Verification

`PWN::Banner.respond_to?(:get)` after the
module is loaded. Read the source for parameter names.
