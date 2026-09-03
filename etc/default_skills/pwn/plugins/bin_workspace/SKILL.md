---
name: pwn-plugins-binworkspace
description: Drive PWN::Plugins::BinWorkspace from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::BinWorkspace
  source: pwn/plugins/bin_workspace.rb
---

# PWN::Plugins::BinWorkspace

Persistent per-binary analysis workspace keyed by sha256.

## When to use

Call `PWN::Plugins::BinWorkspace` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/bin_workspace.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::BinWorkspace.help
PWN::Plugins::BinWorkspace.for(opts)
```

## Public methods

- `for`
- `annotate`
- `notes`
- `authors`
- `help`

## Source

`pwn/plugins/bin_workspace.rb`

## Verification

`PWN::Plugins::BinWorkspace.respond_to?(:for)` after the
module is loaded. Read the source for parameter names.
