# Sessions - Transcript Persistence

Every `pwn-ai` conversation (top-level *and* per-persona in a Swarm) is
appended as JSON-per-line to `~/.pwn/sessions/<id>.jsonl`.

![Sessions ↔ Cron ↔ Swarm](diagrams/sessions-cron-automation.svg)

## Why keep transcripts?

- `learning_reflect(session_id:)` mines them for durable lessons → Memory.
- `learning_distill_skill(name:, session_id:)` turns a winning run into a
  reusable Skill.
- `sessions_view` lets you (or a later agent) re-read exactly what happened.
- Swarm maps each persona to its own session so its private context survives
  across `agent_ask` calls.

## Tools

| Tool | Purpose |
|---|---|
| `sessions_current` | The id *this* conversation is being written to |
| `sessions_list(limit:)` | Newest-first index (id · size · mtime · lines) |
| `sessions_view(session_id:, truncate:)` | Read entries |
| `sessions_delete(session_id:)` | Prune noisy/dev transcripts so `reflect` corpus stays clean |
| `sessions_stats` | totals across the whole directory |

## File format

```json
{"role":"system","ts":"2026-07-07T22:08:02Z","content":"..."}
{"role":"user","ts":"...","content":"..."}
{"role":"assistant","ts":"...","content":"...","tool_calls":[...]}
{"role":"tool","ts":"...","name":"shell","content":"..."}
```

**See also:** [Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Swarm](Swarm.md) · [Persistence](Persistence.md)

[← Home](Home.md)
