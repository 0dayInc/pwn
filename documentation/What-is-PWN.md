# What is PWN

PWN (pronounced /pōn/ or "pone") is a powerful open-source **offensive cybersecurity automation framework** and **continuous security integration platform**.

## Core Purpose

- Rapidly discover zero-days
- Automate exploitation and post-exploitation
- Perform advanced web application penetration testing
- Conduct source code analysis (SAST)
- Orchestrate infrastructure reconnaissance at scale
- Execute AI-augmented autonomous security operations

## Architecture Highlights

PWN provides over 60 production-grade plugins, full LLM integration with tool-calling agents, persistent memory, reusable skills, session/cron management, and a highly interactive REPL (Pry-powered) for prototyping and driving complex security workflows.

All core automation primitives are open to promote trust, peer review, and collaborative innovation in adversarial security.

## Key Components

- `PWN::Plugins::*` — 66+ specialized modules
- `PWN::AI::*` — Multi-LLM clients + autonomous agent
- `PWN::SAST` — Static analysis & test case generation
- `PWN::Reports` — Automated reporting
- `PWN::Memory`, `Sessions`, `Cron`, `Skills`, `Config`
- `PWN::Driver` — Custom automation packages

See:
- [How PWN Works](How-PWN-Works.md)
- [Plugins](Plugins.md)
- [pwn-ai Agent](pwn-ai-Agent.md)

[[Diagrams]]
