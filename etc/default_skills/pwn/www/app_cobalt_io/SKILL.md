---
name: pwn-www-appcobaltio
description: Drive PWN::WWW::AppCobaltIO from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::AppCobaltIO
  source: pwn/www/app_cobalt_io.rb
---

# PWN::WWW::AppCobaltIO

This plugin supports app.cobalt.io actions.

## When to use

Call `PWN::WWW::AppCobaltIO` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/app_cobalt_io.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::AppCobaltIO.help
PWN::WWW::AppCobaltIO.open(opts)
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

`pwn/www/app_cobalt_io.rb`

## Verification

`PWN::WWW::AppCobaltIO.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
