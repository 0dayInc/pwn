---
name: pwn-plugins-frida
description: Drive PWN::Plugins::Frida from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Frida
  source: pwn/plugins/frida.rb
---

# PWN::Plugins::Frida

Frida attach/spawn + script injection.

## When to use

Call `PWN::Plugins::Frida` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/frida.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Frida.help
PWN::Plugins::Frida.required_bins(opts)
```

## Public methods

- `required_bins`
- `ps`
- `attach`
- `spawn`
- `ssl_pinning_script`
- `authors`
- `help`

## Source

`pwn/plugins/frida.rb`

## Verification

`PWN::Plugins::Frida.respond_to?(:required_bins)` after the
module is loaded. Read the source for parameter names.
