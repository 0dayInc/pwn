---
name: pwn-ai-agent-registry
description: Drive PWN::AI::Agent::Registry from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Registry
  source: pwn/ai/agent/registry.rb
---

# PWN::AI::Agent::Registry

Central registry for pwn-ai agent tools. Each file under lib/pwn/ai/agent/tools/*.rb calls +PWN::AI::Agent::Registry.register(...)+ at load time to declare a JSON-Schema (what the LLM sees) and a handler lambda (what pwn runs). Registry.definitions(...) returns the OpenAI-format +tools:+ array; Registry.lookup(name:) returns the entry for dispatch. Import chain (circular-import safe): agent/registry.rb (no deps on tool files) ^ agent/tools/*.rb (require registry, call .register at top level) ^ agent/loop.rb (calls Registry.discover then .definitions) DYNAMIC TOOL-SET SLIMMING (local-model scaffolding) --------------------------------------------------- Shipping all ~47 tool schemas on every call overwhelms a 35B local model — it mis-routes (extro_rf_tune for a git question) because the choice space is huge. When PWN::Env[:ai][:agent][:tool_router] is truthy (or nil while active==:ollama) AND definitions(relevance:) is passed, the pool is reduced to CORE_TOOLS + the top-K keyword-ranked matches. Routing accuracy is fed back into Metrics under name:'tool_router' so the router itself becomes a learned component.

## When to use

Call `PWN::AI::Agent::Registry` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/registry.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Registry.help
PWN::AI::Agent::Registry.register(opts)
```

## Public methods

- `register`
- `lookup`
- `all`
- `toolsets`
- `definitions`
- `preference_order`
- `apply_preference`
- `rank`
- `discover`
- `authors`
- `help`

## Source

`pwn/ai/agent/registry.rb`

## Verification

`PWN::AI::Agent::Registry.respond_to?(:register)` after the
module is loaded. Read the source for parameter names.
