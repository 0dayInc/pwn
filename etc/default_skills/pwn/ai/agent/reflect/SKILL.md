---
name: pwn-ai-agent-reflect
description: Drive PWN::AI::Agent::Reflect from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Reflect
  source: pwn/ai/agent/reflect.rb
---

# PWN::AI::Agent::Reflect

PWN::AI::Agent::Reflect is the inward-facing counterpart to PWN::AI::Agent::Extrospection. Where Extrospection looks OUTWARD at the world the agent operates in (host state, toolchain, network, threat-intel), Reflect looks INWARD - it lets pwn hand a request to the active AI engine and reflect on its own artifacts, transcripts, findings, code, or decisions. This module is gated by `PWN::Env[:ai][:module_reflection]` so that potentially-sensitive local data is never shipped to a remote LLM unless the operator has explicitly opted in via pwn-vault / config. It is the single choke-point every PWN::AI::Agent::* domain agent (Assembly, BurpSuite, GQRX, HackerOne, SAST, VulnGen, ...) routes through when it wants an LLM opinion on locally-produced data, and it is also what PWN::AI::Agent::Learning.reflect uses to distill session transcripts into durable PWN::Memory lessons. TEACHER-STUDENT REFLECTION -------------------------- When PWN::Env[:ai][:reflect_engine] (or opts[:engine]) names a different provider than :active, Reflect.on temporarily flips :active for the duration of the introspection call. This lets a local Ollama model EXECUTE the task while a frontier model WRITES the durable lessons about it — the local model then reads back distilled reasoning it could never have produced itself. IMPLEMENTATION NOTE ------------------- Reflect.on MUST call the engine's text .chat API directly — never Loop.run. Nesting Loop.run re-enters TaskSummarizer/PromptBuilder/ auto_introspect and produces SystemStackError at the Pry after_read boundary whenever module_reflection is enabled. A thread-local depth counter still gates re-entrant Reflect.on (e.g. chat_for_plan inside an outer agent turn that also judges/reflects).

## When to use

Call `PWN::AI::Agent::Reflect` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/reflect.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Reflect.help
PWN::AI::Agent::Reflect.on(opts)
```

## Public methods

- `on`
- `authors`
- `help`

## Source

`pwn/ai/agent/reflect.rb`

## Verification

`PWN::AI::Agent::Reflect.respond_to?(:on)` after the
module is loaded. Read the source for parameter names.
