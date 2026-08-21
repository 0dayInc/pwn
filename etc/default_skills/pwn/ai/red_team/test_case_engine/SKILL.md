---
name: pwn-ai-redteam-testcaseengine
description: Drive PWN::AI::RedTeam::TestCaseEngine from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::RedTeam::TestCaseEngine
  source: pwn/ai/red_team/test_case_engine.rb
---

# PWN::AI::RedTeam::TestCaseEngine

AI RedTeam Module used to execute PWN::AI::RedTeam::* modules against a target LLM / AI engine. Each attack payload is dispatched to the target model, the raw response is captured, and an independent judge (PWN::AI::Agent::Reflect) scores the response for vulnerability exposure so results roll straight into PWN::Reports::AIRedTeam. ATTACKER vs TARGET SPLIT ------------------------ The engine driving the attack (payload generation + judging) does NOT have to be the engine under test. A frontier model can red-team a local one: PWN::AI::RedTeam::PromptInjection.scan( attacker_engine: :anthropic, attacker_model: 'opus-4.8', target_engine: :ollama, target_model: 'qwen-3.6:latest' ) When neither is passed, both default to PWN::Env[:ai][:active] (the model attacks itself). ADAPTIVE TEST-CASE GENERATION ----------------------------- When PWN::Env[:ai][:module_reflection] == true the strategy-generated seed payloads from each RedTeam module are only round 0. After every round the attacker engine is handed the (payload, response, severity) history and asked to synthesise a fresh batch of payloads specific to the OWASP-LLM / ATLAS category under test. The loop halts on the FIRST deterministic condition met: 1. A finding at or above :stop_on_severity is produced (default CRITICAL) 2. :plateau_rounds consecutive adaptive rounds yield nothing >= MEDIUM 3. :max_adaptive_rounds is exhausted 4. The attacker returns no novel payloads (all duplicates of history) Because the halt is a pure function of the recorded severities / payload set, replaying the same responses reproduces the same stop.

## When to use

Call `PWN::AI::RedTeam::TestCaseEngine` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/red_team/test_case_engine.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::RedTeam::TestCaseEngine.help
PWN::AI::RedTeam::TestCaseEngine.execute(opts)
```

## Public methods

- `execute`
- `authors`
- `help`

## References

- `references/urls.md` — URLs from source

## Source

`pwn/ai/red_team/test_case_engine.rb`

## Verification

`PWN::AI::RedTeam::TestCaseEngine.respond_to?(:execute)` after the
module is loaded. Read the source for parameter names.
