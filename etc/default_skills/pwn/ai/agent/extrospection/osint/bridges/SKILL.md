---
name: pwn-ai-agent-extrospection-osintbridges
description: Drive PWN::AI::Agent::Extrospection::OSINTBridges from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Extrospection::OSINTBridges
  source: pwn/ai/agent/extrospection/osint/bridges.rb
---

# PWN::AI::Agent::Extrospection::OSINTBridges

Local-tool OSINT bridges for PWN::AI::Agent::Extrospection.osint. Wraps host binaries (theHarvester, spiderfoot, amass, recon-ng) already common on Kali / offensive-tooling images, parses their JSON/CSV output, and returns compact structured hits so they behave like any other feed. Every bridge: * checks binary presence first (returns {skipped:} when absent) * runs passive-only / bounded (timeouts, `-passive`, module lists) * NEVER launches a GUI or web UI

## When to use

Call `PWN::AI::Agent::Extrospection::OSINTBridges` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/extrospection/osint/bridges.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Extrospection::OSINTBridges.help
PWN::AI::Agent::Extrospection::OSINTBridges.help(opts)
```

## Public methods

- `authors`
- `help`

## Source

`pwn/ai/agent/extrospection/osint/bridges.rb`

## Verification

`PWN::AI::Agent::Extrospection::OSINTBridges.respond_to?(:authors)` after the
module is loaded. Read the source for parameter names.
