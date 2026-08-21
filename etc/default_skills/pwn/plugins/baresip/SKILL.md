---
name: pwn-plugins-baresip
description: Drive PWN::Plugins::BareSIP from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BareSIP
  source: pwn/plugins/baresip.rb
---

# PWN::Plugins::BareSIP

This plugin is used for interacting w/ baresip over a screen session.

## When to use

Call `PWN::Plugins::BareSIP` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/baresip.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BareSIP.help
PWN::Plugins::BareSIP.start(opts)
```

## Public methods

- `start`
- `baresip_exec`
- `stop`
- `parse_target_file`
- `apply_src_num_rules`
- `dial_target_in_list`
- `recon`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/baresip.rb`

## Verification

`PWN::Plugins::BareSIP.respond_to?(:start)` after the
module is loaded. Read the source for parameter names.
