---
name: pwn-ai-agent-swarm
description: Drive PWN::AI::Agent::Swarm from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Swarm
  source: pwn/ai/agent/swarm.rb
---

# PWN::AI::Agent::Swarm

Native multi-agent orchestration for pwn-ai. Swarm replaces the legacy `pwn-irc` mechanism (inspircd + weechat + PRIVMSG-flattened .chat calls) with first-class sub-agents built on top of PWN::AI::Agent::Loop.run. Each persona is a full tool-calling agent — Memory, Skills, Learning, Metrics and Extrospection all apply — so the self-improvement loop covers the whole swarm. ~/.pwn/agents.yml # persona registry ~/.pwn/swarm/<swarm_id>/bus.jsonl # append-only message bus ~/.pwn/swarm/<swarm_id>/personas.json# persona -> PWN::Sessions id Cross-session / cross-process communication == another pwn-ai (or a PWN::Cron job) calling Swarm.ask/debate with the same swarm_id and reading the same bus.jsonl. No daemon required.

## When to use

Call `PWN::AI::Agent::Swarm` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/swarm.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Swarm.help
PWN::AI::Agent::Swarm.personas(opts)
```

## Public methods

- `personas`
- `spawn`
- `retire`
- `create`
- `list`
- `bus_append`
- `bus_tail`
- `ask`
- `debate`
- `broadcast`
- `map_targets`
- `fact_record`
- `facts_prompt`
- `authors`
- `help`

## Source

`pwn/ai/agent/swarm.rb`

## Verification

`PWN::AI::Agent::Swarm.respond_to?(:personas)` after the
module is loaded. Read the source for parameter names.
