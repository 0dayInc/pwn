---
name: pwn-ai-agent-loop
description: Drive PWN::AI::Agent::Loop from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Loop
  source: pwn/ai/agent/loop.rb
---

# PWN::AI::Agent::Loop

The agent conversation loop: build system prompt → call LLM with tools → if tool_calls: dispatch, append role:'tool' results, loop → else: return text. This replaces the regex-ReAct in PWN::Plugins::REPL :pwn_ai_hook with native function-calling. State (memory, skills, sessions) is all externalised — Loop.run is stateless aside from the messages array it builds. NEGATIVE-FEEDBACK CLOSURE ------------------------- Loop.run is where "learn from mistakes, don't repeat them" is actually enforced. On EVERY failed dispatch it: 1. Records the (tool, normalised_error) fingerprint into PWN::AI::Agent::Mistakes with a PERSISTENT cross-session count. 2. Reads that count back and, if it OR the in-turn count reaches REPEAT_THRESHOLD, prepends a hard "REPEATED FAILURE — change approach" guard to the tool result the model sees next. 3. Appends Mistakes.correction_hint (seen N×, sig, KNOWN FIX: …) so a previously-discovered fix is handed straight back to the model on the FIRST recurrence in a new session — it does not have to fail 3× again to re-learn what it already knew. PromptBuilder.mistakes_block re-injects the top open mistakes and top known fixes into the system prompt of every future turn. COMPLETION ---------- The original request is the completion signal. TaskSummarizer and Policy are advisory (compass / rank). Loop keeps calling CORE_TOOLS until that request is done or truly blocked, then stops. LOCAL-MODEL SCAFFOLDING ----------------------- When the active engine is :ollama (or the corresponding :agent flags are set) Loop.run additionally: * threads request → PromptBuilder for relevance-ranked MEMORY, * threads request → Registry.definitions(relevance:) for a slimmed tool set (:tool_router), * splices Learning.exemplars_for(request:) between system and user as few-shot behaviour retrieval, * runs a plan-then-act pre-pass (:plan_first) so the model externalises a tool plan before its first dispatch, * escalates to a frontier persona for a 3-line corrective hint once ≥ ESCALATE_AFTER_FAILS in-turn failures accumulate (:escalation_persona) — the local model still produces the final answer so Learning/Metrics stay attributed to :ollama.

## When to use

Call `PWN::AI::Agent::Loop` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/loop.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Loop.help
PWN::AI::Agent::Loop.debug_on(opts)
```

## Public methods

- `debug_on`
- `catalog_lookup`
- `world_knowledge`
- `needs_host_work`
- `ollama_wire_messages`
- `openai_wire_messages`
- `request_intent`
- `run`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/agent/loop.rb`

## Verification

`PWN::AI::Agent::Loop.respond_to?(:debug_on)` after the
module is loaded. Read the source for parameter names.
