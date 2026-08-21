---
name: pwn-www-bugcrowd
description: Drive PWN::WWW::BugCrowd from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::BugCrowd
  source: pwn/www/bug_crowd.rb
---

# PWN::WWW::BugCrowd

This plugin supports bugcrowd.com actions.

## When to use

Call `PWN::WWW::BugCrowd` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/bug_crowd.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::BugCrowd.help
PWN::WWW::BugCrowd.open(opts)
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

`pwn/www/bug_crowd.rb`

## Verification

`PWN::WWW::BugCrowd.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
