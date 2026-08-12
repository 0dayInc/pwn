# How PWN Works

PWN is five layers, each visible in the source tree. Edges only go
**down** one layer (or sideways within a layer), which is why the diagrams
below have no criss-crossing lines.

![Overall Architecture](diagrams/overall-pwn-architecture.svg)

## L0 - Actors

Humans (`pwn` REPL, `pwn-ai` TUI), CI runners (`pwn --ai "..."`, `bin/pwn_*`),
LLM providers (over HTTPS), and targets (hosts, web apps, clouds, radios,
hardware).

## L1 - Entry points (`bin/`)

| Entry | File | Purpose |
|---|---|---|
| `pwn` REPL | `lib/pwn/plugins/repl.rb` | Pry with `PWN::` pre-loaded + custom commands |
| `pwn-ai` | `lib/pwn/ai/agent/loop.rb` | Agent TUI inside the REPL |
| `pwn --ai PROMPT` | `bin/pwn` | Headless one-shot agent (CI-friendly) |
| `pwn setup` | `lib/pwn/setup.rb` · `bin/pwn_setup` | Post-install doctor + capability provisioner + `--migrate` state doctor (also `pwn --setup[=PROFILE]`) |
| `bin/pwn_*` | 53 files | Thin OptionParser wrappers over one plugin each |
| `PWN::Cron` | `lib/pwn/cron.rb` | Scheduled jobs → any of the above (nightly self-play + weekly weight-loop seeded by default) |

## L2 - AI agent core (`lib/pwn/ai/agent/`)

| Module | Role |
|---|---|
| `Loop` | plan → **TaskSummarizer** briefs → dispatch tool_calls → observe → repeat until final answer; tightens runway when recent turns exhausted the budget |
| **`TaskSummarizer`** | Executive UX: LLM/heuristic `request_kind` gates plans (only autonomous goals, including host-evidence Qs) - English tasks primary - `emit_plan!` · `about_to` as `task k/n` + via tools · Loop `plan_context` injection · clearer `plan_idx` advance |
| `Registry` | JSON-Schema function definitions grouped into 12 **toolsets** · **82 tools** |
| `Dispatch` / `Result` | execute a tool, capture stdout/value/error/duration |
| `PromptBuilder` | inject MEMORY / SKILLS / LEARNING / **KNOWN MISTAKES + FIXES** / METRICS / EXTROSPECTION blocks |
| `Metrics` · `Learning` · `Reflect` | **introspection** - how well am I doing? |
| `Mistakes` | **negative feedback** - fingerprint failures, do NOT repeat, `[REPEATING]`/`[REGRESSED]`, inline `correction_hint` |
| **`Reward`** | outcome `judge` · per-step process credit · `sentinel` (proxy vs judge drift) · `semantic_ok` · DPO `preferences.jsonl` |
| **`Curriculum`** | mistake-driven self-play `practice` · `counterfactual` A/B · tool-armed `critic` · `red_team_plan` · `hindsight` (HER) · `train_and_gate` regression-gated LoRA |
| `Extrospection` | **extrospection** - on-demand world sensing (`intel` · **`verify`** · **`watch`** · **`rf_tune`** · **`osint`** · `serial` · `telecomm` · `packet` · `vision` · `voice`) + ambient baseline (host · net · toolchain · repo · env · **rf** · **web**) joined to introspection via `correlate` |
| `Swarm` | multi-agent personas over a shared JSONL bus |

See [Agent Tool Registry](Agent-Tool-Registry.md) for every tool the LLM can
call, and [Reinforcement Learning](Reinforcement-Learning.md) for how
`Reward` + `Curriculum` close the weight-level loop.

## L3 - Capability namespaces (`lib/pwn/*`)

`Plugins` (66) · `SAST` (48) · `WWW` (21) · `AWS` (90) · `SDR` · `Blockchain` ·
`Bounty` · `Reports` · `FFI` · `Banner` · **`Setup`** · **`Migrate`**. Each is
a plain module of `public_class_method def self.x(opts = {})` methods -
callable the same way from the REPL, from `pwn_eval`, or from a driver.

## L4 - Persistence (`~/.pwn/`)

Everything the framework remembers between processes lives in one directory.
`PWN::Migrate` (schema-stamped, idempotent, dry-run capable) verifies and
autofixes every file in it after a `gem update pwn`:

![~/.pwn map](diagrams/persistence-filesystem.svg)

See [Persistence](Persistence.md) for the layout of each file and
[Installation § Upgrading](Installation.md#upgrading--pwn-state-migration-pwnmigrate)
for the migrator.

## The feedback loop

L2 exists to close this loop on every turn - successes become skills and
lessons, **failures become fingerprinted mistakes with fixes**, **world state
is sensed on demand** (`extro_verify` / `extro_watch` / `extro_rf_tune` /
`extro_osint` / `extro_serial` / `extro_telecomm` / `extro_packet` /
`extro_vision` / `extro_voice` / `extro_intel`) and correlated against those
failures, an **LLM judge scores the final answer** and a **process reward
model tags each tool step**, and **all six prompt blocks** (MEMORY · SKILLS ·
LEARNING · KNOWN MISTAKES/FIXES · TOOL EFFECTIVENESS · EXTROSPECTION) are
re-injected into the next system prompt.
Nightly cron practices the top unresolved Mistakes; weekly cron builds a
LoRA and only promotes it if it beats the previous adapter on that same
mistake set:

![Self-improvement loop](diagrams/pwn-ai-feedback-learning-loop.svg)

**Next:** [pwn REPL](pwn-REPL.md) · [pwn-ai Agent](pwn-ai-Agent.md) ·
[Reinforcement Learning](Reinforcement-Learning.md)

[← Home](Home.md)
