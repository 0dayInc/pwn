---
name: pwn-www-hackerone
description: Drive PWN::WWW::HackerOne from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::HackerOne
  source: pwn/www/hacker_one.rb
---

# PWN::WWW::HackerOne

This plugin supports hackerone.com actions.

## When to use

Call `PWN::WWW::HackerOne` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/hacker_one.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::HackerOne.help
PWN::WWW::HackerOne.open(opts)
```

## Public methods

- `open`
- `get_bounty_programs`
- `get_scope_details`
- `get_hacktivity`
- `save_burp_target_config_file`
- `login`
- `logout`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/hacker_one.rb`

## Verification

`PWN::WWW::HackerOne.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
