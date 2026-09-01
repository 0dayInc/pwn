---
name: pwn-ai-agent-tools-swarmmap
description: Drive PWN::Ai::Agent::Tools::SwarmMap from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::SwarmMap
  source: pwn/ai/agent/tools/swarm_map.rb
---

# PWN::Ai::Agent::Tools::SwarmMap

Public API for PWN::Ai::Agent::Tools::SwarmMap.

## When to use

Call `PWN::Ai::Agent::Tools::SwarmMap` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tools/swarm_map.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Ai::Agent::Tools::SwarmMap.help
PWN::Ai::Agent::Tools::SwarmMap.help(opts)
```

## Public methods

- _(no public class methods parsed)_

## Source

`pwn/ai/agent/tools/swarm_map.rb`

## Verification

`PWN::Ai::Agent::Tools::SwarmMap.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
