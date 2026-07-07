# `pwn-ai` — The Autonomous Agent

`pwn-ai` is a natural-language front end to everything in `PWN::`. You describe
the goal; the agent plans a sequence of tool calls (`pwn_eval`, `shell`,
`memory_*`, `skill_*`, `extro_*`, `agent_*`, …), executes them against the live
process, observes the results, and loops until it can give you a final answer.

## Two ways to run it

```text
# 1. Interactive TUI (inside the pwn REPL)
pwn[v0.5.616]:001 >>> pwn-ai
✨ pwn-ai · anthropic · session 20260707_220802_3f39791f
> Use NmapIt to sweep 10.0.0.0/24, then TransparentBrowser via Burp on any
  host with 443 open, active-scan, and give me a Reports::SAST summary.
```

```bash
# 2. Headless one-shot (CI-friendly)
$ pwn --ai "run bin/pwn_sast against ./src and push findings to DefectDojo"
```

## Anatomy of a turn

1. **PromptBuilder** assembles the system prompt: your request + MEMORY block +
   SKILLS list + LEARNING stats + EXTROSPECTION block.
2. **Loop** sends it to the active `PWN::AI::<Engine>` client.
3. Provider replies with `tool_calls` → **Dispatch** executes each one via the
   [Registry](Agent-Tool-Registry.md), **Metrics** records duration/success.
4. Results are appended to the message list; go to 2.
5. When the reply has *no* tool_calls it's the **final answer** →
   `Learning.auto_reflect` and `Extrospection.auto_extrospect` fire (if
   enabled), transcript is flushed to `~/.pwn/sessions/`.

![Self-improvement loop](diagrams/pwn-ai-feedback-learning-loop.svg)

## What the agent can call

10 toolsets · 45+ tools — full table at
[Agent Tool Registry](Agent-Tool-Registry.md).

The two that matter most:

| Tool | Reach |
|---|---|
| `pwn_eval` | **Any** Ruby in-process — the whole `PWN::` namespace, `require`, monkey-patch, everything |
| `shell` | **Any** OS command on the host |

Everything else (memory, skills, learning, extrospection, cron, swarm,
sessions, metrics) is a convenience wrapper the model can discover from the
schema alone.

## Delegating to other agents

`agent_ask`, `agent_debate`, `agent_broadcast` spin up **sub-agents** (each a
full `Loop.run` under a persona overlay) that share a JSONL bus. See
[Swarm](Swarm.md).

## Tips

- SHIFT+ENTER = newline, ENTER = submit.
- `back` / `exit` returns to the plain REPL.
- Set `ai.agent.max_iters` in `~/.pwn/config.yml` if long tasks get truncated.
- Disable `auto_reflect` during noisy fuzz loops
  (`learning_auto_reflect_toggle(enabled: false)`), re-enable for the summary
  turn.

**See also:** [AI Integration](AI-Integration.md) ·
[Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Extrospection](Extrospection.md) · [Swarm](Swarm.md) · [Cron](Cron.md)

[← Home](Home.md)
