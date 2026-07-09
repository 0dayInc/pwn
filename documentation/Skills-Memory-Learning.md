# Memory · Skills · Learning · Mistakes · Metrics — Introspection

The **inward-facing** half of the pwn-ai feedback loop: how the agent measures
its own performance, turns wins into permanent capability, and — critically —
**learns from its own mistakes so it does not repeat them**.

![Memory / Skills detail](diagrams/memory-skills-detailed.svg)

## The five stores

| Store | File | Write tool | Read tool | Injected as |
|---|---|---|---|---|
| **Memory** | `memory.json` | `memory_remember` | `memory_recall` | `MEMORY` block — durable facts / prefs / lessons / env |
| **Skills** | `skills/*.md` | `skill_create` · `learning_distill_skill` | `skill_list` · `skill_view` | `SKILLS` list — reusable procedures + `references:` (CWE/CVE/ATT&CK/NIST/URL) |
| **Learning** | `learning.jsonl` | `learning_note_outcome` · `learning_reflect` | `learning_outcomes` · `learning_stats` | `LEARNING` block — recent outcomes + success_rate |
| **Mistakes** | `mistakes.json` | `mistakes_record` · `mistakes_resolve` · *auto on failure* | `mistakes_list` | `KNOWN MISTAKES` + `KNOWN FIXES` blocks — do-NOT-repeat + do-THIS-instead |
| **Metrics** | `metrics.json` | *automatic* (every Dispatch) | `metrics_summary` | `TOOL EFFECTIVENESS` block — steer tool choice |

## The lifecycle of a lesson

```text
1. Dispatch runs a tool              → Metrics.record(tool, ok?, ms)
   ↳ tool FAILED?                    → Mistakes.record(tool, error)  (count++, cross-session)
   ↳ same sig ≥3×?                   → guard_repeated_failure + inline correction_hint
2. Agent senses the world (opt)      → extro_verify / watch / rf_tune / intel / observe
   ↳ extro_verify → :refuted         → Mistakes.record(tool:'assumption', …)  # proactive
   ↳ extro_verify → :confirmed       → observe(:intel, ttl:30d)
3. Final answer produced             → Learning.auto_introspect(session_id)
   ↳ if auto_extrospect enabled      → Extrospection.auto_extrospect  # AUTO_SECTIONS only
4. Reflect finds a durable insight   → Memory.remember(lesson_xxxx, …)
5. A whole workflow succeeded         → Learning.distill_skill(name, session_id, references:)
6. Found a fix for a mistake          → mistakes_resolve(sig, fix) → Memory :lesson "AVOID X — FIX: Y"
7. Next launch: PromptBuilder injects all six blocks → the model already knows:
     MEMORY · SKILLS · LEARNING · KNOWN MISTAKES/FIXES · TOOL EFFECTIVENESS · EXTROSPECTION
```

`extro_correlate` is the **join** — it tells the agent whether a failure was
*its* fault (belongs in Mistakes) or *the world* changed (kernel upgrade,
dongle unplugged, target DOM moved). See **[Mistakes](Mistakes.md)** for the
negative-feedback mechanics and **[Extrospection](Extrospection.md)** for the
outward half.

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
| `PWN::AI::Agent::Extrospection.revalidate_memory` *(cron)* | MEMORY `:fact` entries getting **stale** — browser-verifies every one containing a CVE/version/URL and prefixes refuted ones `[UNVERIFIED yyyy-mm-dd]` |
| `learning_reset(confirm: true)` | dev-experiment noise polluted success_rate |
| `mistakes_reset(confirm: true)` | new host/engagement — prior failure patterns no longer apply |
| `metrics_reset(confirm: true)` | fixed a broken tool; stale 0 % is misleading |
| `skill_delete(name)` | auto-distilled skill turned out low-quality |
| `learning_auto_introspect_toggle(enabled: false)` | during noisy fuzz loops |

## Example questions that trigger Introspection

Natural-language prompts that should fire the **inward** half of the learning
feedback loop (Memory · Skills · Learning · Mistakes · Metrics). Pair these with
the outward catalog in [Extrospection](Extrospection.md#example-questions-that-trigger-extrospection)
when deciding which side of the loop to exercise.

### Memory (`memory_remember`, `memory_recall`, `memory_forget`, `memory_clear`)

- “Remember that our preferred AI engine for long recon chains is grok-4.5.”
- “What do we already know about OpenSSH 8.2p1 from prior sessions?”
- “Forget the stale fact about the old HackRF serial — it was replaced.”
- “Store this as a durable lesson: always back up source files before patching.”
- “Recall any preference we set for Burp/ZAP proxy ports.”

### Skills (`skill_list`, `skill_view`, `skill_create`, `skill_add_reference`, `skill_delete`, `learning_distill_skill`)

- “What skills do we have for SQLi / RDS / GQRX scanning?”
- “Show me the full body of `vulnerability_research_fundamentals`.”
- “Distill this successful session into a reusable skill for ADS-B capture.”
- “Add CWE-89 and T1190 as references on the `sqli_union_enum` skill.”
- “Delete the low-quality auto-distilled skill from yesterday’s fuzz loop.”
- “Create a skill that walks GQRX remote control → `extro_rf_tune` → observe.”

### Learning outcomes & reflection (`learning_note_outcome`, `learning_reflect`, `learning_outcomes`, `learning_stats`, `learning_consolidate`)

- “Record that the video-generation pipeline succeeded (ffmpeg + flite).”
- “What was our success rate over the last 50 attempts?”
- “Reflect on session `20260709_172057_49594079` and extract durable lessons.”
- “Show only the recent *failures* tagged with `extrospection` or `rf`.”
- “Consolidate near-duplicate MEMORY lessons — cap at 200 entries.”
- “Reset learning outcomes; the dev experiment noise polluted the rate.” *(destructive)*

### Mistakes / negative feedback (`mistakes_list`, `mistakes_record`, `mistakes_resolve`, `mistakes_reset`)

- “What mistakes keep recurring across sessions?”
- “I just assumed Registry had `.list` — record that as an assumption mistake.”
- “Resolve signature `1b6f88b46ce2` — the fix is use `.all` / `.lookup`, not `.list`.”
- “Show only unresolved fingerprints sorted by count.”
- “That last approach was wrong; fingerprint it so we don’t repeat it.”
- “Wipe mistakes.json for a clean slate on the new engagement host.” *(destructive)*

### Metrics / tool effectiveness (`metrics_summary`, `metrics_reset`)

- “Which tools have the lowest success rate right now?”
- “How often has `shell` been called, and what’s its avg duration?”
- “Is `extro_rf_tune` healthier than the old GQRX helpers by metrics?”
- “Reset metrics after we fixed the broken tool so the 0 % doesn’t steer us away.” *(destructive)*

### Sessions / transcripts (`sessions_list`, `sessions_view`, `sessions_current`, `sessions_stats`, `sessions_delete`)

- “What’s the active session id?”
- “List the last 10 sessions and their sizes.”
- “Open session X and show the last 50 turns (truncated).”
- “How much disk are session transcripts using overall?”
- “Delete the noisy fuzz-experiment transcript so reflect() stays high-signal.”

### Loop toggles & housekeeping

- “Disable auto-introspect while we fuzz; re-enable for the summary turn.”
- “Is auto-introspect currently on?”
- “Revalidate MEMORY facts that contain CVEs / versions / URLs.” *(joins Extrospection.revalidate_memory)*
- “Why did that tool start failing — my fault or world drift?” → `extro_correlate` then Mistakes vs Learning

### Short “trigger” patterns the agent should recognize

| Pattern | Likely tools |
|--------|----------------|
| “Remember / recall / forget that…” | `memory_remember` / `memory_recall` / `memory_forget` |
| “What skills do we have for… / distill this” | `skill_*` / `learning_distill_skill` |
| “Did that work? / note the outcome / success rate” | `learning_note_outcome` / `learning_stats` |
| “Reflect on this session / extract lessons” | `learning_reflect` / `sessions_current` |
| “Don’t do that again / that was wrong / resolve…” | `mistakes_record` / `mistakes_resolve` / `mistakes_list` |
| “Which tools are unhealthy / avg duration” | `metrics_summary` |
| “What did we run in session X / active session” | `sessions_view` / `sessions_current` |
| “Disable reflection while we fuzz” | `learning_auto_introspect_toggle` |

Contrast with **Extrospection** examples: weather in Chicago, “what’s on 101.1”,
CVE fact-checks, and host drift are *outside-world* senses. The table above is
purely *self* measurement — how well the agent did, what it must stop repeating,
and which procedures to promote permanently.

**See also:** [Mistakes](Mistakes.md) — the negative-feedback half ·
[Extrospection](Extrospection.md) — the outward-facing half ·
[Sessions](Sessions.md) · [Persistence](Persistence.md)

[← Home](Home.md)
