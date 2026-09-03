---
name: pwn-ai-agent-tools-debuglane
description: Drive PWN::Ai::Agent::Tools::DebugLane from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::Ai::Agent::Tools::DebugLane
  source: pwn/ai/agent/tools/debug_lane.rb
---

# PWN::Ai::Agent::Tools::DebugLane

Public API for PWN::Ai::Agent::Tools::DebugLane.

## When to use

Call `PWN::Ai::Agent::Tools::DebugLane` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/tools/debug_lane.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::Ai::Agent::Tools::DebugLane.help
PWN::Ai::Agent::Tools::DebugLane.help(opts)
```

## Public methods

- _(no public class methods parsed)_

## Source

`pwn/ai/agent/tools/debug_lane.rb`

## Verification

`PWN::Ai::Agent::Tools::DebugLane.respond_to?(:help)` after the
module is loaded. Read the source for parameter names.
