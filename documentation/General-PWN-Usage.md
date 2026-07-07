# General PWN Usage

## Launching PWN

```bash
$ pwn
pwn[v0.5.613]:001 >>>
```

## Essential Commands Inside REPL

- `PWN.help` — overview of top-level modules
- `PWN::Plugins.constants.sort` — list all plugins
- `pwn-ai` — start the autonomous AI agent TUI (recommended)
- `pwn-asm` — assembly/REPL for low-level work
- `pwn-ai-memory`, `pwn-ai-sessions`, `pwn-ai-cron` — management helpers
- `back` — exit `pwn-ai` mode
- Full Ruby expressions work at any time.

## Recommended Workflow

1. Launch `pwn`
2. Start `pwn-ai`
3. Give natural language tasks that leverage plugins, skills, memory.
4. Use `SHIFT+ENTER` for multi-line prompts.

## Updating PWN

See [Installation](Installation.md).

## Persistent State

Everything lives under `~/.pwn/`:
- `skills/`
- `memory.json`
- `learning.jsonl`
- `metrics.json`
- sessions, cron jobs, etc.

[[Diagrams]]
