# How PWN Works

PWN is five layers, each visible in the source tree. Edges only ever go
**down** one layer (or sideways within a layer), which is why the diagrams
below have no criss-crossing lines.

![Overall Architecture](diagrams/overall-pwn-architecture.svg)

## L0 — Actors

Humans (`pwn` REPL, `pwn-ai` TUI), CI runners (`pwn --ai "…"`, `bin/pwn_*`),
LLM providers (over HTTPS), and targets (hosts, web apps, clouds, radios,
hardware).

## L1 — Entry points  (`bin/`)

| Entry | File | Purpose |
|---|---|---|
| `pwn` REPL | `lib/pwn/plugins/repl.rb` | Pry with `PWN::` pre-loaded + custom commands |
| `pwn-ai` | `lib/pwn/ai/agent/loop.rb` | Agent TUI inside the REPL |
| `pwn --ai PROMPT` | `bin/pwn` | Headless one-shot agent (CI-friendly) |
| `bin/pwn_*` | 52 files | Thin OptionParser wrappers over one plugin each |
| `PWN::Cron` | `lib/pwn/cron.rb` | Scheduled jobs → any of the above |

## L2 — AI agent core  (`lib/pwn/ai/agent/`)

| Module | Role |
|---|---|
| `Loop` | plan → dispatch tool_calls → observe → repeat until final answer |
| `Registry` | JSON-Schema function definitions grouped into 10 **toolsets** · 52 tools |
| `Dispatch` / `Result` | execute a tool, capture stdout/value/error/duration |
| `PromptBuilder` | inject MEMORY / SKILLS / LEARNING / **KNOWN MISTAKES + FIXES** / METRICS / EXTROSPECTION blocks |
| `Metrics` · `Learning` | **introspection** — how well am I doing? |
| `Mistakes` | **negative feedback** — fingerprint failures, do NOT repeat, `[REPEATING]`/`[REGRESSED]`, inline `correction_hint` |
| `Extrospection` | **extrospection** — what does the world look like? (host · net · toolchain · repo · env · **rf**) |
| `Swarm` | multi-agent personas over a shared JSONL bus |

See [Agent Tool Registry](Agent-Tool-Registry.md) for every tool the LLM can call.

## L3 — Capability namespaces  (`lib/pwn/*`)

`Plugins` (66) · `SAST` (48) · `WWW` (21) · `AWS` (90) · `SDR` · `Blockchain` ·
`Bounty` · `Reports` · `FFI` · `Banner`. Each is a plain module of
`public_class_method def self.x(opts = {})` methods — callable identically from
the REPL, from `pwn_eval`, or from a driver.

## L4 — Persistence  (`~/.pwn/`)

Everything the framework remembers between processes lives in one directory:

![~/.pwn map](diagrams/persistence-filesystem.svg)

See [Persistence](Persistence.md) for the byte-level layout of each file.

## The feedback loop

The reason L2 exists is to close this loop on every turn — successes
become skills/lessons, **failures become fingerprinted mistakes with fixes**,
and both are re-injected into the very next system prompt:

![Self-improvement loop](diagrams/pwn-ai-feedback-learning-loop.svg)

**Next:** [pwn REPL](pwn-REPL.md) · [pwn-ai Agent](pwn-ai-Agent.md)

[← Home](Home.md)
