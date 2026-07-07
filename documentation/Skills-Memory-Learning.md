# Memory · Skills · Learning · Metrics — Introspection

The **inward-facing** half of the pwn-ai feedback loop: how the agent measures
its own performance and turns wins into permanent capability.

![Memory / Skills detail](diagrams/memory-skills-detailed.svg)

## The four stores

| Store | File | Write tool | Read tool | Injected as |
|---|---|---|---|---|
| **Memory** | `memory.json` | `memory_remember` | `memory_recall` | `MEMORY` block — durable facts / prefs / lessons / env |
| **Skills** | `skills/*.md` | `skill_create` · `learning_distill_skill` | `skill_list` · `skill_view` | `SKILLS` list — reusable procedures + `references:` (CWE/CVE/ATT&CK/NIST/URL) |
| **Learning** | `learning.jsonl` | `learning_note_outcome` · `learning_reflect` | `learning_outcomes` · `learning_stats` | `LEARNING` block — recent outcomes + success_rate |
| **Metrics** | `metrics.json` | *automatic* (every Dispatch) | `metrics_summary` | `TOOL EFFECTIVENESS` block — steer tool choice |

## The lifecycle of a lesson

```text
1. Dispatch runs a tool           → Metrics.record(tool, ok?, ms)
2. Final answer produced          → Learning.auto_reflect(session_id)
3. Reflect finds a durable insight → Memory.remember(lesson_xxxx, …)
4. A whole workflow succeeded      → Learning.distill_skill(name, session_id, references:)
5. Next launch: PromptBuilder injects all four blocks → the model already knows.
```

## Skill file format

```markdown
---
references:
  - CWE-89
  - T1190
  - https://portswigger.net/web-security/sql-injection
---
# sqli_union_enum

1. Confirm injection with `' AND 1=1 --`.
2. Find column count with `ORDER BY n`.
3. …

## References
- CWE-89
- T1190
```

`PWN::Config.parse_skill_references` reads both the YAML front-matter **and**
the `## References` section, deduplicates, and exposes them via
`skill_view(name)[:references]`.

## Housekeeping

| Tool | When |
|---|---|
| `learning_consolidate(max_entries: 200)` | MEMORY block getting long/noisy |
| `learning_reset(confirm: true)` | dev-experiment noise polluted success_rate |
| `metrics_reset(confirm: true)` | fixed a broken tool; stale 0 % is misleading |
| `skill_delete(name)` | auto-distilled skill turned out low-quality |
| `learning_auto_reflect_toggle(enabled: false)` | during noisy fuzz loops |

**See also:** [Extrospection](Extrospection.md) — the outward-facing half ·
[Sessions](Sessions.md) · [Persistence](Persistence.md)

[← Home](Home.md)
