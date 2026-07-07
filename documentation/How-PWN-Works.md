# How PWN Works

PWN is structured as a Ruby gem with a rich `PWN::` namespace.

## Visual Architecture Overview

See the full set of **[Data Flow Diagrams](Diagrams.md)** (18+ SVGs) for detailed visualization of data flows, including:

![Overall PWN Architecture](diagrams/overall-pwn-architecture.svg)

- [PWN-AI Feedback Learning Loop](diagrams/pwn-ai-feedback-learning-loop.svg) — the core self-improving closed loop
- [REPL Prototyping](diagrams/pwn-repl-prototyping.svg)
- [History → Drivers & Skills](diagrams/history-to-drivers.svg)
- [AI Tool Calling Integration](diagrams/ai-integration-tool-calling.svg)
- [Plugin Ecosystem](diagrams/plugin-ecosystem.svg)
- And many more specific workflows (Pen Testing, Web, Fuzzing, SAST, RE, etc.)

## Namespace Overview

| Namespace          | Description |
|--------------------|-------------|
| `PWN::Plugins::*`  | 67+ specialized modules (see [Plugins](Plugins.md)) |
| `PWN::AI::*`       | Multi-provider LLM clients + autonomous `PWN::AI::Agent` |
| `PWN::SAST`        | Static application security testing + test case generation |
| `PWN::Reports`     | Automated reporting from scans, agents, findings |
| `PWN::Memory`      | Persistent facts across sessions |
| `PWN::Sessions`    | Record / replay conversations and workflows |
| `PWN::Cron`        | Scheduled autonomous tasks |
| `PWN::Skills`      | Reusable markdown procedures (distilled from successful runs) |
| `PWN::Config`      | Environment + credential management |
| `PWN::Driver`      | Framework for custom security automation packages |

## Primary Interfaces

1. **pwn REPL** — Pry-powered interactive shell (launched via `pwn` command). Full `PWN` namespace pre-loaded.
2. **pwn-ai** — Autonomous AI agent TUI inside the REPL (highly recommended). Uses tool calling for `pwn_eval`, shell, skills, memory, etc.
3. **Custom Drivers** — See `/opt/pwn/bin/` examples and [Drivers](Drivers.md).

## LLM Tool Calling

The agent can:
- Execute any PWN plugin method directly
- Run shell commands
- Recall/remember facts
- Distill new skills from successful workflows
- Use multiple LLM providers (OpenAI, Anthropic, Gemini, Grok OAuth, Ollama, ...)

Example:
```
pwn-ai
> Use NmapIt to scan target.example.com, spider with TransparentBrowser, proxy via BurpSuite, run SAST if source available, then generate report.
```

See the Diagrams and:
- [pwn REPL](pwn-REPL.md)
- [pwn-ai Agent](pwn-ai-Agent.md)
- [Plugins](Plugins.md)
- [AI Integration](AI-Integration.md)
- [Skills, Memory & Learning](Skills-Memory-Learning.md)

