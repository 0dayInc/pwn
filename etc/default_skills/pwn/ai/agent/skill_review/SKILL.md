---
name: pwn-ai-agent-skillreview
description: Drive PWN::AI::Agent::SkillReview from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::SkillReview
  source: pwn/ai/agent/skill_review.rb
---

# PWN::AI::Agent::SkillReview

Decide whether a completed task should update or create a skill. recommend is the default. auto-safe writes only a small verified addition.

## When to use

Call `PWN::AI::Agent::SkillReview` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/skill_review.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::SkillReview.help
PWN::AI::Agent::SkillReview.review(opts)
```

## Public methods

- `review`
- `review_turn`
- `note_reuse`
- `authors`
- `help`

## Source

`pwn/ai/agent/skill_review.rb`

## Verification

`PWN::AI::Agent::SkillReview.respond_to?(:review)` after the
module is loaded. Read the source for parameter names.
