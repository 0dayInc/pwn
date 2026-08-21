---
name: pwn-ai-agent-promptbuilder
description: Drive PWN::AI::Agent::PromptBuilder from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::PromptBuilder
  source: pwn/ai/agent/prompt_builder.rb
---

# PWN::AI::Agent::PromptBuilder

Assembles the system prompt for every Loop.run invocation from durable on-disk state: PWN::Env persona, host environment probe, PWN::Memory facts, and PWN::Skills index. Re-injection IS the persistence mechanism: this is rebuilt fresh on every user turn, so a memory_remember / skill_create from the prior turn shows up here with no extra wiring. ENGINE-AWARE BUDGETING ---------------------- Local models (Ollama) drown when handed the same 6-8 KB of MEMORY / METRICS / MISTAKES / EXTROSPECTION context that a frontier model shrugs off. .budget shrinks each block for :ollama (or whatever PWN::Env[:ai][<engine>][:prompt_budget] says) so the small model spends its attention on the request, not the harness. RELEVANCE-RANKED MEMORY ----------------------- When Loop.run passes request: through, the MEMORY block is populated by PWN::MemoryIndex.recall_semantic (embedding cosine over ~/.pwn/memory.idx) instead of a recency dump — the 6 memories a small model can afford are the 6 that actually matter for THIS turn.

## When to use

Call `PWN::AI::Agent::PromptBuilder` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/prompt_builder.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::PromptBuilder.help
PWN::AI::Agent::PromptBuilder.build(opts)
```

## Public methods

- `build`
- `budget`
- `authors`
- `help`

## Source

`pwn/ai/agent/prompt_builder.rb`

## Verification

`PWN::AI::Agent::PromptBuilder.respond_to?(:build)` after the
module is loaded. Read the source for parameter names.
