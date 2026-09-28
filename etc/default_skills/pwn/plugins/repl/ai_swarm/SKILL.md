---
name: pwn-plugins-repl-aiswarm
description: Drive PWN::Plugins::REPL::AISwarm from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Plugins::REPL::AISwarm
  source: pwn/plugins/repl/ai_swarm.rb
---

# PWN::Plugins::REPL::AISwarm

Console-owned controller over the existing Swarm persona APIs.

## When to use

Call `PWN::Plugins::REPL::AISwarm` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/plugins/repl/ai_swarm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Plugins::REPL::AISwarm.help
PWN::Plugins::REPL::AISwarm.help(opts)
```

## Public methods

- `authors`
- `help`

## Source

`pwn/plugins/repl/ai_swarm.rb`

## Verification

`PWN::Plugins::REPL::AISwarm.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
