# Skills, Memory & Learning

One of PWN's most powerful features is its self-improving closed loop.

## Memory (`PWN::Memory`)

Persistent facts, preferences, lessons, and environment data stored in `~/.pwn/memory.json`.

Use from REPL / agent:
- `PWN::Memory.remember(key, value, category: :fact)`
- `PWN::Memory.recall(query)`

Injected into every future `pwn-ai` session.

## Skills

Reusable, versionable markdown procedures stored in `~/.pwn/skills/`.

- Created automatically via distillation of successful agent runs.
- Manually via `skill_create` or editing YAML+markdown files.
- Contain front-matter `references:` (CWE, CVE, ATT&CK, NIST, URLs).
- Exposed to the agent and listed via `skill_list` / `skill_view`.

Example skills:
- `deep_exploitation`
- `vulnerability_research_fundamentals`
- `xai_grok_oauth_device_flow`

## Learning Loop

- `PWN::AI::Agent::Metrics` — per-tool success rate + duration (`~/.pwn/metrics.json`)
- `PWN::AI::Agent::Learning` — outcomes, reflections, skill distillation (`~/.pwn/learning.jsonl`)
- Successful workflows become durable skills available to all future sessions.

## Management Commands (REPL)

- `pwn-ai-memory`
- `pwn-ai-sessions`
- `pwn-ai-cron`
- `skill_list`, `skill_view`, `skill_create`, `skill_add_reference`

This system turns one-off wins into institutional knowledge.

[[Diagrams]]
