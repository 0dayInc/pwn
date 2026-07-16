# How PWN Works

PWN is five layers, each visible in the source tree. Edges only ever go
**down** one layer (or sideways within a layer), which is why the diagrams
below have no criss-crossing lines.

![Overall Architecture](diagrams/overall-pwn-architecture.svg)

## L0 - Actors

Humans (`pwn` REPL, `pwn-ai` TUI), CI runners (`pwn --ai "..."`, `bin/pwn_*`),
LLM providers (over HTTPS), and targets (hosts, web apps, clouds, radios,
hardware).

## L1 - Entry points  (`bin/`)

| Entry | File | Purpose |
|---|---|---|
| `pwn` REPL | `lib/pwn/plugins/repl.rb` | Pry with `PWN::` pre-loaded + custom commands |
| `pwn-ai` | `lib/pwn/ai/agent/loop.rb` | Agent TUI inside the REPL |
| `pwn --ai PROMPT` | `bin/pwn` | Headless one-shot agent (CI-friendly) |
| `pwn setup` | `lib/pwn/setup.rb` · `bin/pwn_setup` | Post-install doctor + capability provisioner + `--migrate` state doctor (also `pwn --setup[=PROFILE]`) |
| `bin/pwn_*` | 52 files | Thin OptionParser wrappers over one plugin each |
| `PWN::Cron` | `lib/pwn/cron.rb` | Scheduled jobs → any of the above (nightly self-play + weekly weight-loop seeded by default) |

## L2 - AI agent core  (`lib/pwn/ai/agent/`)

| Module | Role |
|---|---|
| `Loop` | plan → dispatch tool_calls → observe → repeat until final answer |
| `Registry` | JSON-Schema function definitions grouped into 10 **toolsets** · **71 tools** |
| `Dispatch` / `Result` | execute a tool, capture stdout/value/error/duration |
| `PromptBuilder` | inject MEMORY / SKILLS / LEARNING / **KNOWN MISTAKES + FIXES** / METRICS / EXTROSPECTION blocks |
| `Metrics` · `Learning` · `Reflect` | **introspection** - how well am I doing? |
| `Mistakes` | **negative feedback** - fingerprint failures, do NOT repeat, `[REPEATING]`/`[REGRESSED]`, inline `correction_hint` |
| **`Reward`** | **R1** ORM `judge` · **R2** PRM per-step credit · **R3** `sentinel` reward-hacking detector · **R4** `semantic_ok` · **W1** DPO `preferences.jsonl` |
| **`Curriculum`** | **S1** mistake-driven self-play `practice` · **S2** `counterfactual` A/B · **S3** tool-armed `critic` · **S4** `red_team_plan` · **C3** `hindsight` (HER) · **W2** `train_and_gate` regression-gated LoRA |
| `Extrospection` | **extrospection** - on-demand world sensing (`intel` · **`verify`** · **`watch`** · **`rf_tune`** · **`osint`** · `serial` · `telecomm` · `packet` · `vision` · `voice`) + ambient baseline (host · net · toolchain · repo · env · **rf** · **web**) joined to introspection via `correlate` |
| `Swarm` | multi-agent personas over a shared JSONL bus |

See [Agent Tool Registry](Agent-Tool-Registry.md) for every tool the LLM can
call, and [Reinforcement Learning](Reinforcement-Learning.md) for how
`Reward` + `Curriculum` close the weight-level loop.

## L3 - Capability namespaces  (`lib/pwn/*`)

`Plugins` (66) · `SAST` (48) · `WWW` (21) · `AWS` (90) · `SDR` · `Blockchain` ·
`Bounty` · `Reports` · `FFI` · `Banner` · **`Setup`** · **`Migrate`**. Each is
a plain module of `public_class_method def self.x(opts = {})` methods -
callable identically from the REPL, from `pwn_eval`, or from a driver.

## L4 - Persistence  (`~/.pwn/`)

Everything the framework remembers between processes lives in one directory.
`PWN::Migrate` (schema-stamped, idempotent, dry-run capable) verifies and
autofixes every file in it after a `gem update pwn`:

![~/.pwn map](diagrams/persistence-filesystem.svg)

See [Persistence](Persistence.md) for the byte-level layout of each file and
[Installation § Upgrading](Installation.md#upgrading--pwn-state-migration-pwnmigrate)
for the migrator.

## The feedback loop

The reason L2 exists is to close this loop on every turn - successes
become skills/lessons, **failures become fingerprinted mistakes with fixes**,
**world-state is sensed on demand** (`extro_verify` / `extro_watch` /
`extro_rf_tune` / `extro_osint` / `extro_serial` / `extro_telecomm` /
`extro_packet` / `extro_vision` / `extro_voice` / `extro_intel`) and
correlated against those failures, an **LLM judge scores the final** and a
**process reward model tags each tool step**, and **all six prompt blocks**
(MEMORY · SKILLS · LEARNING · KNOWN MISTAKES/FIXES · TOOL EFFECTIVENESS ·
EXTROSPECTION) are re-injected into the very next system prompt.
Nightly cron practises the top unresolved Mistakes; weekly cron cuts a
LoRA and only promotes it if it beats the previous adapter on that same
mistake set:

![Self-improvement loop](diagrams/pwn-ai-feedback-learning-loop.svg)

**Next:** [pwn REPL](pwn-REPL.md) · [pwn-ai Agent](pwn-ai-Agent.md) ·
[Reinforcement Learning](Reinforcement-Learning.md)

[← Home](Home.md)
