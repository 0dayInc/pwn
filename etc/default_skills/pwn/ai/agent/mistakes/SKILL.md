---
name: pwn-ai-agent-mistakes
description: Drive PWN::AI::Agent::Mistakes from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::Mistakes
  source: pwn/ai/agent/mistakes.rb
---

# PWN::AI::Agent::Mistakes

PWN::AI::Agent::Mistakes is the negative-feedback half of the pwn-ai learning loop. Where Learning records WHAT WORKED and Metrics records HOW OFTEN a tool worked, Mistakes records SPECIFIC FAILURE PATTERNS with a stable fingerprint so the agent can (a) recognise it is repeating itself, (b) be told exactly what not to do again in every future system prompt, and (c) capture the FIX once one is found so the avoidance lesson becomes an actionable correction. A "mistake" is keyed by sha12(tool + normalised_error). Normalisation strips volatile bits (paths, hex addresses, line numbers, timestamps, UUIDs, PIDs) so "NoMethodError ... at foo.rb:42" and "... at foo.rb:99" collapse to one signature and its :count climbs — that count IS the repeat detector. Closed loop (why it does NOT repeat mistakes): Loop.run --(tool failure)---------> Mistakes.record (persist + count++) Loop.run --(same sig fails ≥N)----> guard_repeated_failure (uses PERSISTENT count, so triggers on the 1st recurrence in a new session, not the 3rd) Loop.run --(failure w/ known fix)-> inline "KNOWN FIX: …" (self-corrects next iter) Loop.run --(user says "wrong")----> check_user_correction (flip last outcome + record) PromptBuilder <-------------------- Mistakes.to_context (DO-NOT-REPEAT + KNOWN-FIXES) model --(tool call)---------------> mistakes_record / mistakes_resolve

## When to use

Call `PWN::AI::Agent::Mistakes` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/mistakes.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::Mistakes.help
PWN::AI::Agent::Mistakes.load(opts)
```

## Public methods

- `load`
- `save`
- `signature`
- `error_class`
- `family`
- `find`
- `for_tool`
- `record`
- `resolve`
- `top`
- `extinguish`
- `extinguish_parked`
- `park`
- `operator_inbox`
- `to_context`
- `correction_hint`
- `note_hint_outcome`
- `correction`
- `check_user_correction`
- `lean`
- `reset`
- `effective_count`
- `authors`
- `help`
- `correction?`
- `extinguish!`
- `extinguish_parked!`
- `lean!`

## Source

`pwn/ai/agent/mistakes.rb`

## Verification

`PWN::AI::Agent::Mistakes.respond_to?(:load)` after the
module is loaded. Read the source for parameter names.
