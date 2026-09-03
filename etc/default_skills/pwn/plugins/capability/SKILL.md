---
name: pwn-plugins-capability
description: Drive PWN::Plugins::Capability from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Capability
  source: pwn/plugins/capability.rb
---

# PWN::Plugins::Capability

Operator-approved capability elevation (never auto-sudo).

## When to use

Call `PWN::Plugins::Capability` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/capability.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Capability.help
PWN::Plugins::Capability.request(opts)
```

## Public methods

- `request`
- `grantable_caps`
- `authors`
- `help`

## Source

`pwn/plugins/capability.rb`

## Verification

`PWN::Plugins::Capability.respond_to?(:request)` after the
module is loaded. Read the source for parameter names.
