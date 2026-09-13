---
name: pwn-plugins-repl-mesh
description: Drive PWN::Plugins::REPL::Mesh from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::Mesh
  source: pwn/plugins/repl/mesh.rb
---

# PWN::Plugins::REPL::Mesh

pwn-mesh REPL mode.

## When to use

Call `PWN::Plugins::REPL::Mesh` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/mesh.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::Mesh.help
PWN::Plugins::REPL::Mesh.add_commands(opts)
```

## Public methods

- `add_commands`
- `authors`
- `help`

## Source

`pwn/plugins/repl/mesh.rb`

## Verification

`PWN::Plugins::REPL::Mesh.respond_to?(:add_commands)` after the
module is loaded. Read the source for parameter names.
