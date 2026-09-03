---
name: pwn-plugins-emulator
description: Drive PWN::Plugins::Emulator from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::Emulator
  source: pwn/plugins/emulator.rb
---

# PWN::Plugins::Emulator

Unicorn-backed single-function emulation with a stub backend for tests.

## When to use

Call `PWN::Plugins::Emulator` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/emulator.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::Emulator.help
PWN::Plugins::Emulator.emulate(opts)
```

## Public methods

- `emulate`
- `authors`
- `help`

## Source

`pwn/plugins/emulator.rb`

## Verification

`PWN::Plugins::Emulator.respond_to?(:emulate)` after the
module is loaded. Read the source for parameter names.
