---
name: pwn-ai-agent-tasksummarizer
description: Drive PWN::AI::Agent::TaskSummarizer from pwn_eval.
license: MIT
allowed-tools: [pwn, pwn_eval]
metadata:
  bundled: true
  generated: true
  module: PWN::AI::Agent::TaskSummarizer
  source: pwn/ai/agent/task_summarizer.rb
---

# PWN::AI::Agent::TaskSummarizer

High-level executive brief of the work the agent is about to do. Every pwn-ai request is a goal. There is no statement/question/goal request type. English tangible tasks are an advisory compass: 1. plan(request:) — break the goal into ordered plain-English tasks 2. about_to(tools:) — per tool-batch brief led by "task k/n" 3. active_task_prompt — injected into Loop as a compass only 4. record! emits an advancement brief when plan_idx moves Never dumps raw commands or tool results into the task row — those stay on the per-tool lines the REPL already prints. REPL on_tool contract (repl.rb): on_tool.call('task', full_summary_text, '') # result MUST be empty # → [ ts → pwn-ai → task ] <full summary, no truncation> on_tool.call('shell', args, result) # real tool

## When to use

Call `PWN::AI::Agent::TaskSummarizer` from `pwn_eval` when the task needs this module.
Do not reimplement it in shell.

## Methodologies

Generated from `pwn/ai/agent/task_summarizer.rb`. Prefer the public class methods below.
Class methods take `(opts = {})` and read `opts`.

## How to call

```ruby
PWN::AI::Agent::TaskSummarizer.help
PWN::AI::Agent::TaskSummarizer.enabled(opts)
```

## Public methods

- `enabled`
- `verbose`
- `llm_plan_enabled`
- `every_n`
- `interval_s`
- `fresh`
- `needs_task_breakdown`
- `plan`
- `format_plan`
- `emit_plan`
- `chat_for_plan`
- `parse_llm_tasks`
- `fallback_decompose`
- `heuristic_decompose`
- `about_to`
- `active_task`
- `unfinished_tasks`
- `plan_open`
- `plan_context`
- `relevance_query`
- `active_task_prompt`
- `canonical_request`
- `tool_jargon_task`
- `parse_outline_tasks`
- `unify_plan`
- `apply_prm_advancement`
- `record`
- `emit`
- `flush`
- `authors`
- `help`

## Source

`pwn/ai/agent/task_summarizer.rb`

## Verification

`PWN::AI::Agent::TaskSummarizer.respond_to?(:enabled)` after the
module is loaded. Read the source for parameter names.
