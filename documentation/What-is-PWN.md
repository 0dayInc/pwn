# What is PWN

**PWN** (pronounced /pon/ - "pone") is an open-source **offensive security
automation** framework, shipped as a Ruby gem.

It gives security researchers, red teamers, bug-bounty hunters, and DevSecOps
engineers one scriptable surface over the offensive toolchain - OSINT and
network discovery, web/cloud/hardware/radio work, reporting, and disclosure -
with a **tool-calling AI agent** on top that can run the same methods.

## In numbers

| Namespace | Count | What it is |
|---|---|---|
| `PWN::Plugins::*` | **67** | Wrappers for external and native tooling (Burp, Nmap, Metasploit, Shodan, browsers, serial, ...) |
| `PWN::SAST::*` | **48** | Static-analysis rules across C/Java/Go/Python/Ruby/Scala/PHP/TS |
| `PWN::AWS::*` | **90** | One module per AWS service for cloud enumeration |
| `PWN::WWW::*` | **22** | Site-specific browser automations (HackerOne, BugCrowd, GitHub, Google, LinkedIn, ...) |
| `PWN::SDR::*` | **6** (+ **20** protocol decoders + Base/DSP) | GQRX, FlipperZero, RFIDler, SonMicro, band tables, `Decoder::{ADSB,POCSAG,RDS,LoRa,...}` |
| `PWN::FFI::*` | **8** | Native DSP/RF backends: Volk · Liquid · FFTW · RTLSdr · HackRF · AdalmPluto · SoapySDR · Stdio |
| `PWN::AI::*` | **6** engines | OpenAI, Anthropic, Grok (OAuth device-flow), Gemini, Ollama, Open WebUI |
| `bin/pwn_*` + `pwn` | **54** | Headless CLI executables for CI/CD |
| Agent toolsets | **13** · **87 tools** | terminal · pwn · memory · skills · sessions · learning · metrics · policy · extrospection · cron · swarm · reward · curriculum |

## Three ways to use it

1. **`pwn` REPL** - a Pry shell with the whole `PWN::` namespace loaded.
   Prototype an attack chain one method call at a time.
2. **`pwn-ai`** - a natural-language TUI (or `pwn --ai "..."` one-shot) where an
   LLM plans and runs those same method calls, shows **TaskSummarizer** executive
   briefs on long turns, records what worked, and improves over time.
3. **`bin/pwn_*` drivers** - thin CLIs over the plugins, for cron and CI/CD.

## What makes it different

- **Everything is Ruby, everything is a method.** No YAML DSLs, no black-box
  plugins. If you can call it in the REPL, the AI agent can call it, a driver
  can call it, and a cron job can call it.
- **Closed feedback loop.** Metrics + Learning + **Reward** (outcome and process
  judges, sentinel) + **Curriculum** (mistake-driven self-play, hindsight relabel,
  export-ready LoRA gate) + **Policy** (live tabular Q-learning and REINFORCE on
  each turn, advisory rank only) on the introspection side; Snapshot + Drift +
  Intel + Verify on the extrospection side; joined by `extro_correlate`, which
  tells the agent whether a failure was *its* fault or *the world* changed - and
  writes the lesson back into the next prompt.
- **Native multi-agent.** `PWN::AI::Agent::Swarm` runs personas (each a full
  tool-calling agent, optionally on a *different* LLM engine) that debate,
  broadcast, and share an append-only bus - no IRC daemon, no external service.
- **Self-healing state.** `PWN::Setup` (doctor/provisioner) + `PWN::Migrate`
  (schema-stamped `~/.pwn` verifier/auto-migrator) make `gem install --verbose pwn` →
  `pwn setup` the full install and upgrade path on every supported OS.

![Overall Architecture](diagrams/overall-pwn-architecture.svg)

**Next:** [Why PWN](Why-PWN.md) · [How PWN Works](How-PWN-Works.md) ·
[Installation](Installation.md)

[← Home](Home.md)
