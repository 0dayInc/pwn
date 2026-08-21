---
name: pwn-plugins
description: Drive PWN::Plugins from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins
  source: pwn/plugins.rb
---

# PWN::Plugins

This file, using the autoload directive loads Plugins modules into memory only when they're needed. For more information, see: http://www.rubyinside.com/ruby-techniques-revealed-autoload-1652.html

## When to use

Call `PWN::Plugins` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins.help
PWN::Plugins.help(opts)
```

## Public methods

- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins.rb`

## Verification

`PWN::Plugins.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
