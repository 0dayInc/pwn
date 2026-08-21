---
name: pwn-ai-agent-metrics
description: Drive PWN::AI::Agent::Metrics from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Metrics
  source: pwn/ai/agent/metrics.rb
---

# PWN::AI::Agent::Metrics

PWN::AI::Agent::Metrics is the telemetry layer of the pwn-ai learning loop. Every tool dispatch performed by PWN::AI::Agent::Loop is recorded here (name, success, duration, last error) and persisted to ~/.pwn/metrics.json. PromptBuilder re-injects a compact effectiveness summary into the system prompt on every turn, so the model gains awareness of which tools historically succeed vs. fail on THIS host and can adapt its tool selection accordingly. This is one half of the closed feedback loop that lets pwn-ai continuously make itself smarter (the other half is PWN::AI::Agent::Learning). PER-ENGINE SEGMENTATION ----------------------- A local Ollama model and a frontier model do NOT have the same per-tool success rate — blending them mis-advises the local model about itself. Every record now also increments an :engines[<engine>] sub-bucket; summary/to_context accept engine: to surface only that engine's telemetry so the TOOL EFFECTIVENESS block becomes a genuine per-engine learned policy.

## When to use

Call `PWN::AI::Agent::Metrics` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/metrics.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Metrics.help
PWN::AI::Agent::Metrics.load(opts)
```

## Public methods

- `load`
- `save`
- `record`
- `summary`
- `to_context`
- `proxy_trust`
- `ucb`
- `thompson`
- `advantage`
- `prm_advantage`
- `prm_n`
- `record_step_reward`
- `record_judge`
- `judge_confidence`
- `judge_rate`
- `effective_rate`
- `changepoints`
- `record_calibration`
- `calibration`
- `health_line`
- `reset`
- `authors`
- `help`

## Source

`pwn/ai/agent/metrics.rb`

## Verification

`PWN::AI::Agent::Metrics.respond_to?(:load)` after the
module is loaded. Read the source for parameter names.
