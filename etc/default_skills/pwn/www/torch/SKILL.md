---
name: pwn-www-torch
description: Drive PWN::WWW::Torch from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::WWW::Torch
  source: pwn/www/torch.rb
---

# PWN::WWW::Torch

This plugin supports Torch (Tor Search Engine) actions.

## When to use

Call `PWN::WWW::Torch` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/www/torch.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::WWW::Torch.help
PWN::WWW::Torch.open(opts)
```

## Public methods

- `open`
- `search`
- `onion`
- `close`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/www/torch.rb`

## Verification

`PWN::WWW::Torch.respond_to?(:open)` after the
module is loaded. Read the source for parameter names.
