---
name: pwn-sast
description: Drive PWN::SAST from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::SAST
  source: pwn/sast.rb
---

# PWN::SAST

This file, using the autoload directive loads SAST modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::SAST` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/sast.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::SAST.help
PWN::SAST.help(opts)
```

## Public methods

- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/sast.rb`

## Verification

`PWN::SAST.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
