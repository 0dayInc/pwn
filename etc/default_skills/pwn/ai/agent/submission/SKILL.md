---
name: pwn-ai-agent-submission
description: Interpret submission outcomes and delivery receipts.
license: MIT
metadata:
  bundled: true
  preserve: true
  module: PWN::AI::Agent::Submission
  source: pwn/ai/agent/submission.rb
---

# PWN::AI::Agent::Submission

Use `PWN::AI::Agent::Submission.stats` to inspect aggregate submission outcomes.
`by_stage` shows where requests ended. `by_delivery` reports whether the console
observed delivery. Neither says whether the answer was correct.

Only submissions with an independent check contribute to the false-block and
false-completion rates. A `nil` rate means there were no checked cases for that
rate, not that the rate was zero.

Receipt changes belong to the submitting controller, the presentation owner,
and the independent verifier. Do not change a receipt to complete a task.
