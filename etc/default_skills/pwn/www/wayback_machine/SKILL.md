---
name: pwn-www-waybackmachine
description: Drive PWN::WWW::WaybackMachine from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::WaybackMachine
  source: pwn/www/wayback_machine.rb
---

# PWN::WWW::WaybackMachine

This plugin supports Wayback Machine actions.

## When to use

Call `PWN::WWW::WaybackMachine` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/wayback_machine.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::WaybackMachine.help
PWN::WWW::WaybackMachine.open(opts)
```

## Public methods

- `open`
- `search`
- `timetravel`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/wayback_machine.rb`

## Verification

`PWN::WWW::WaybackMachine.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
