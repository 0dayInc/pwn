# `pwn-ai` — The Autonomous Agent

`pwn-ai` is a natural-language front end to everything in `PWN::`. You describe
the goal; the agent plans a sequence of tool calls (`pwn_eval`, `shell`,
`memory_*`, `skill_*`, `mistakes_*`, `extro_*`, `agent_*`, …), executes them
against the live process, observes the results, and loops until it can give you
a final answer — **learning from every failure so it doesn't repeat it**.

## Two ways to run it

```text
# 1. Interactive TUI (inside the pwn REPL)
pwn[v0.5.618]:001 >>> pwn-ai
✨ pwn-ai · anthropic · session 20260707_225041_d7f2f3bb
> Use NmapIt to sweep 10.0.0.0/24, then TransparentBrowser via Burp on any
  host with 443 open, active-scan, and give me a Reports::SAST summary.
```

```bash
# 2. Headless one-shot (CI-friendly)
$ pwn --ai "run bin/pwn_sast against ./src and push findings to DefectDojo"
```

## Anatomy of a turn

1. **PromptBuilder** assembles the system prompt: your request + MEMORY block +
   SKILLS list + LEARNING stats + **KNOWN MISTAKES / KNOWN FIXES** +
   TOOL EFFECTIVENESS + EXTROSPECTION block.
2. **Loop** checks the incoming message against `Mistakes::CORRECTION_RX` — if
   it reads like *"no, that's wrong"* the previous outcome is flipped to
   `success:false` and fingerprinted.
3. Loop sends the prompt to the active `PWN::AI::<Engine>` client.
4. Provider replies with `tool_calls` → **Dispatch** executes each one via the
   [Registry](Agent-Tool-Registry.md); **Metrics** records duration/success.
   Any *failure* is fingerprinted into **Mistakes** (`count++`, cross-session)
   and the tool result gets an inline `correction_hint` (`seen N×, sig=…,
   KNOWN FIX: …`) so the very next iteration self-corrects. If the persistent
   count ≥ 3, `guard_repeated_failure` interrupts with an explicit
   *change-approach* instruction.
5. Results are appended to the message list; go to 3.
6. When the reply has *no* tool_calls it's the **final answer** →
   `Learning.auto_introspect` and `Extrospection.auto_extrospect` fire (if
   enabled), transcript is flushed to `~/.pwn/sessions/`.

![Self-improvement loop](diagrams/pwn-ai-feedback-learning-loop.svg)

## What the agent can call

10 toolsets · 54 tools — full table at
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
- Set `ai.agent.max_iters` in `~/.pwn/config.yml` if long tasks get truncated.
- Disable `auto_introspect` during noisy fuzz loops
  (`learning_auto_introspect_toggle(enabled: false)`), re-enable for the summary
  turn.
- Run `mistakes_list` before retrying something that failed last session — the
  fix may already be recorded.

**See also:** [AI Integration](AI-Integration.md) ·
[Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Mistakes](Mistakes.md) · [Extrospection](Extrospection.md) ·
[Swarm](Swarm.md) · [Cron](Cron.md)

[← Home](Home.md)
