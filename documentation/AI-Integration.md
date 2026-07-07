# AI & LLM Integration

PWN integrates deeply with multiple LLMs for both interactive and autonomous operation.

## Supported Providers

- OpenAI
- Anthropic
- Google Gemini
- xAI Grok (full OAuth device flow support, public client)
- Ollama (local)
- Others via extensible client design

## Primary Entry Points

- `PWN::AI::*` (OpenAI, Anthropic, Grok, etc.)
- `PWN::AI::Agent` — the autonomous tool-calling harness
- `pwn-ai` command inside REPL launches the TUI

## Tool Calling

The agent can call:
- `pwn_eval` (full PWN namespace + Ruby)
- `shell`
- skills
- memory (recall/remember)
- learning & metrics

OAuth for Grok is configured via `PWN::Config` and follows modern device-code flows (no client secrets).

See:
- [pwn-ai Agent](pwn-ai-Agent.md)
- [Skills, Memory & Learning](Skills-Memory-Learning.md)
- `lib/pwn/ai/` in source

[[Diagrams]]
