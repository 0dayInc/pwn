---
name: pwn-ai-agent-extrospection
description: Drive PWN::AI::Agent::Extrospection from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Extrospection
  source: pwn/ai/agent/extrospection.rb
---

# PWN::AI::Agent::Extrospection

PWN::AI::Agent::Extrospection is the outward-facing counterpart to PWN::AI::Agent::Learning (introspection). PRIMARY INTENT - on-demand external sensing ------------------------------------------- Quickly explore *external* resources when that produces a more informed answer. Call a sense tool only when the question needs it: "weather in Tokyo" → verify / watch / TransparentBrowser "what's on 101.1 FM?" → rf_tune(freq: "101.1") → RDS / observe(:rf) "CVE for openssl 3.0?" → intel(query:) / verify(claim:, kind: :cve) "did the target change?" → watch(url:) / snapshot(sections: [:web]) Secondary / optional - ambient host baseline -------------------------------------------- snapshot / drift / correlate can record cheap local posture so the agent can tell "I called the API wrong" from "the world moved" (kernel upgrade, dongle unplugged). This is NEVER the reason to launch GUI / JVM / heavy-REPL binaries - those are presence-only. auto_extrospect, when enabled, uses only side-effect-free sections. INTROSPECTIVE (self) EXTROSPECTIVE (world) ---------------------- ------------------------------------- Metrics.record Extrospection.intel/verify/watch/rf_tune (sense) Learning.note_outcome Extrospection.observe (fact) Learning.reflect Extrospection.snapshot/drift (baseline) Learning.stats Extrospection.correlate (self×world) PromptBuilder re-injects Extrospection.to_context on every turn. Persistence: ~/.pwn/extrospection.json across REPL restarts.

## When to use

Call `PWN::AI::Agent::Extrospection` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/extrospection.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Extrospection.help
PWN::AI::Agent::Extrospection.load(opts)
```

## Public methods

- `load`
- `save`
- `snapshot`
- `observe`
- `observations`
- `drift`
- `intel`
- `verify`
- `watch`
- `rf_tune`
- `osint`
- `serial_sense`
- `telecomm`
- `packet_sense`
- `vision`
- `voice_sense`
- `revalidate_memory`
- `correlate`
- `to_context`
- `stats`
- `auto_extrospect`
- `reset`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/agent/extrospection.rb`

## Verification

`PWN::AI::Agent::Extrospection.respond_to?(:load)` after the
module is loaded. Read the source for parameter names.
