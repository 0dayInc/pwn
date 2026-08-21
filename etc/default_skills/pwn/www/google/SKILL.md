---
name: pwn-www-google
description: Drive PWN::WWW::Google from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Google
  source: pwn/www/google.rb
---

# PWN::WWW::Google

This plugin supports Google actions.

## When to use

Call `PWN::WWW::Google` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/google.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Google.help
PWN::WWW::Google.open(opts)
```

## Public methods

- `open`
- `search`
- `search_linkedin_for_employees_by_company`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/google.rb`

## Verification

`PWN::WWW::Google.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
