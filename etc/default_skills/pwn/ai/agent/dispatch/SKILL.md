---
name: pwn-ai-agent-dispatch
description: Drive PWN::AI::Agent::Dispatch from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Dispatch
  source: pwn/ai/agent/dispatch.rb
---

# PWN::AI::Agent::Dispatch

Tool-call dispatch: takes a single tool_call object (OpenAI shape), looks up the registered handler, parses args, runs it, and returns a JSON string suitable for a role:'tool' message. TOLERANT DISPATCH (local-model scaffolding) ------------------------------------------- Local models running on Ollama frequently emit almost- right tool calls: `run_shell` instead of `shell`, trailing commas, single-quoted JSON, arguments as a bare string. Strict parsing burns an iteration and often spirals. Dispatch now: * repair_name — Levenshtein-matches unknown names to the closest registered tool and records a Mistakes fingerprint (source: :repair) so the KNOWN MISTAKES block eventually teaches the model the right name. * parse_args — falls back to a JSON5-ish clean-up pass (strip trailing commas, swap single→double quotes, wrap a bare scalar as the tool's sole required arg). Frontier engines never hit these paths — repair is a no-op when the name/JSON are already valid.

## When to use

Call `PWN::AI::Agent::Dispatch` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/dispatch.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Dispatch.help
PWN::AI::Agent::Dispatch.call(opts)
```

## Public methods

- `call`
- `repair_name`
- `tool_calls_from_text`
- `effect`
- `authors`
- `help`

## Source

`pwn/ai/agent/dispatch.rb`

## Verification

`PWN::AI::Agent::Dispatch.respond_to?(:call)` after the
module is loaded. Read the source for parameter names.
