---
name: pwn-plugins-detonate
description: Drive PWN::Plugins::Detonate from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Detonate
  source: pwn/plugins/detonate.rb
---

# PWN::Plugins::Detonate

Isolated sample detonation. Refuses if podman/isolation is missing.

## When to use

Call `PWN::Plugins::Detonate` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/detonate.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Detonate.help
PWN::Plugins::Detonate.detonate(opts)
```

## Public methods

- `detonate`
- `authors`
- `help`

## Source

`pwn/plugins/detonate.rb`

## Verification

`PWN::Plugins::Detonate.respond_to?(:detonate)` after the
module is loaded. Read the source for parameter names.
