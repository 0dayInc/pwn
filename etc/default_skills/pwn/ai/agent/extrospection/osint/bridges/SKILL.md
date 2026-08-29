---
name: pwn-ai-agent-extrospection
description: Drive PWN::AI::Agent::Extrospection from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Extrospection
  source: pwn/ai/agent/extrospection/osint/bridges.rb
---

# PWN::AI::Agent::Extrospection

Local-tool OSINT bridges for PWN::AI::Agent::Extrospection.osint. Wraps host binaries (theHarvester, spiderfoot, amass, recon-ng) already common on Kali / offensive-tooling images, parses their JSON/CSV output, and returns compact structured hits so they behave like any other feed. Every bridge: * checks binary presence first (returns {skipped:} when absent) * runs passive-only / bounded (timeouts, `-passive`, module lists) * NEVER launches a GUI or web UI

## When to use

Call `PWN::AI::Agent::Extrospection` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/extrospection/osint/bridges.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Extrospection.help
PWN::AI::Agent::Extrospection.auto_extrospect(opts)
```

## Public methods

- `authors`
- `help`
- `auto_extrospect`
- `correlate`
- `drift`
- `intel`
- `load`
- `observations`
- `observe`
- `osint`
- `packet_sense`
- `reset`
- `revalidate_memory`
- `rf_tune`
- `save`
- `serial_sense`
- `snapshot`
- `stats`
- `telecomm`
- `to_context`
- `verify`
- `vision`
- `voice_sense`
- `watch`

## Source

`pwn/ai/agent/extrospection/osint/bridges.rb`

## Verification

`PWN::AI::Agent::Extrospection.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
