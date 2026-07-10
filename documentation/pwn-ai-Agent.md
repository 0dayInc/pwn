# `pwn-ai` — The Autonomous Agent

`pwn-ai` is a natural-language front end to everything in `PWN::`. You describe
the goal; the agent plans a sequence of tool calls (`pwn_eval`, `shell`,
`memory_*`, `skill_*`, `mistakes_*`, `extro_*`, `agent_*`, …), executes them
against the live process, observes the results, and loops until it can give you
a final answer — **learning from every failure so it doesn't repeat it**.

## Two ways to run it

```text
# 1. Interactive TUI (inside the pwn REPL)
pwn[v0.5.622]:001 >>> pwn-ai
✨ pwn-ai · anthropic · session 20260707_225041_d7f2f3bb
> Use NmapIt to sweep 10.0.0.0/24, then TransparentBrowser via Burp on any
  host with 443 open, active-scan, and give me a Reports::SAST summary.
```

```bash
# 2. Headless one-shot (CI-friendly)
$ pwn --ai "run bin/pwn_sast against ./src and push findings to DefectDojo"
```

## Anatomy of a turn

1. **PromptBuilder** assembles the system prompt: your request + **six
   engine-budgeted blocks** — MEMORY (relevance-ranked via `PWN::MemoryIndex`
   when a local embedding model is reachable) · SKILLS · LEARNING ·
   **KNOWN MISTAKES / KNOWN FIXES** · TOOL EFFECTIVENESS (**per-engine**) ·
   **EXTROSPECTION** (live host fp + drift + fresh observations including
   `:rf` now-playing and `:web` DOM watches). `PromptBuilder.budget` shrinks
   each block for local engines so a small model spends its attention on the
   task, not the harness.
2. **Loop** checks the incoming message against `Mistakes::CORRECTION_RX` — if
   it reads like *"no, that's wrong"* the previous outcome is flipped to
   `success:false` and fingerprinted.
3. **Registry** hands Loop the tool schemas — the full set for frontier
   engines, or `CORE_TOOLS` + top-K keyword-relevant when
   `ai.agent.tool_router` is on. *(local)* `Learning.exemplars_for` splices a
   compressed prior-success trace as few-shot; *(local)* `plan_first` forces a
   numbered tool plan before the first dispatch.
4. Loop sends the prompt to the active `PWN::AI::<Engine>` client.
5. Provider replies with `tool_calls` → **Dispatch** executes each one via the
   [Registry](Agent-Tool-Registry.md); **Metrics** records
   `duration/success/engine`. Dispatch is *tolerant* — Levenshtein-repairs
   near-miss tool names and cleans up almost-JSON args, fingerprinting every
   repair into **Mistakes**. Any *failure* is fingerprinted (`count++`,
   cross-session) and the tool result gets an inline `correction_hint`
   (`seen N×, sig=…, KNOWN FIX: …`) so the very next iteration self-corrects.
   If the persistent count ≥ 3, `guard_repeated_failure` interrupts with an
   explicit *change-approach* instruction. *(local)* once in-turn failures
   ≥ `ESCALATE_AFTER_FAILS`, `Loop.escalate` asks the
   `ai.agent.escalation_persona` Swarm persona for a 3-line frontier hint and
   injects it as a synthetic tool result. On-demand sense tools
   (`extro_verify` / `extro_watch` / `extro_rf_tune` / `extro_osint` /
   `extro_serial` / `extro_telecomm` / `extro_packet` / `extro_vision` /
   `extro_voice` / `extro_intel`) fire here when the question needs the
   outside world; a `:refuted` verify is itself recorded as a Mistakes
   `assumption` fingerprint.
6. Results are appended to the message list; go to 4.
7. When the reply has *no* tool_calls it's the **final answer** →
   `Learning.auto_introspect` fires (if enabled): *(local)*
   `fact_check_local_final` auto-`extro_verify`s every CVE / version-shaped
   claim in the answer; `Reflect.on` writes durable lessons via
   `ai.reflect_engine` (teacher-student — a frontier engine may author the
   lesson a local engine reads); when `auto_extrospect` is also on,
   `Extrospection.auto_extrospect` runs (`AUTO_SECTIONS = host/repo/env` only —
   never toolchain/rf/web, never launches Burp/ZAP/msf/gqrx). Transcript is
   flushed to `~/.pwn/sessions/`.

![Self-improvement loop](diagrams/pwn-ai-feedback-learning-loop.svg)

## What the agent can call

10 toolsets · 61 tools — full table at
[Agent Tool Registry](Agent-Tool-Registry.md).

The two that matter most:

| Tool | Reach |
|---|---|
| `pwn_eval` | **Any** Ruby in-process — the whole `PWN::` namespace, `require`, monkey-patch, everything |
| `shell` | **Any** OS command on the host |

Everything else (memory, skills, learning, **mistakes**, extrospection, cron,
swarm, sessions, metrics) is a convenience wrapper the model can discover from
the schema alone.

## Delegating to other agents

`agent_ask`, `agent_debate`, `agent_broadcast` spin up **sub-agents** (each a
full `Loop.run` under a persona overlay) that share a JSONL bus. See
[Swarm](Swarm.md).

## Tips

- SHIFT+ENTER = newline, ENTER = submit.
- `back` / `exit` returns to the plain REPL.
- Set `ai.agent.max_iters` in `~/.pwn/pwn.yaml` if long tasks get truncated.
- Disable `auto_introspect` during noisy fuzz loops
  (`learning_auto_introspect_toggle(enabled: false)`), re-enable for the summary
  turn.
- Run `mistakes_list` before retrying something that failed last session — the
- `ai.agent.tool_router: true` + `ai.agent.plan_first: true` when running on a
  local model — dramatically cuts mis-routing.
- Set `ai.reflect_engine:` to a frontier provider so lessons written to
  `~/.pwn/memory.json` are high-signal even when the *executing* engine is
  local.
- `PWN::AI::Agent::Learning.export_finetune` turns every successful session
  into a supervised dataset (`~/.pwn/finetune/*.jsonl`) — schedule via
  `PWN::Cron` and LoRA the local model on it.
  fix may already be recorded.

**See also:** [AI Integration](AI-Integration.md) ·
[Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Mistakes](Mistakes.md) · [Extrospection](Extrospection.md) ·
[Swarm](Swarm.md) · [Cron](Cron.md)

[← Home](Home.md)
