---
name: pwn-plugins-monkeypatch
description: Drive PWN::Plugins::MonkeyPatch from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::MonkeyPatch
  source: pwn/plugins/monkey_patch.rb
---

# PWN::Plugins::MonkeyPatch

This module provides the ability to centralize monkey patches used in PWN

## When to use

Call `PWN::Plugins::MonkeyPatch` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/monkey_patch.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::MonkeyPatch.help
PWN::Plugins::MonkeyPatch.pry(opts)
```

## Public methods

- `pry`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/plugins/monkey_patch.rb`

## Verification

`PWN::Plugins::MonkeyPatch.respond_to?(:pry)` after the
module is loaded. Read the source for parameter names.
