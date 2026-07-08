# `~/.pwn/` — Persistence Map

Every byte PWN remembers between processes lives here.

![~/.pwn map](diagrams/persistence-filesystem.svg)

| Path | Owner | Format | Reset tool | Purpose |
|---|---|---|---|---|
| `config.yml` | `PWN::Config` | YAML | edit by hand | engines, keys, agent options |
| `memory.json` | `PWN::Memory` | JSON array | `memory_clear` | facts · prefs · lessons · env — injected into every prompt |
| `skills/*.md` | `PWN::Config.load_skills` | Markdown + YAML front-matter | `skill_delete` | reusable procedures + `references:` (CWE/CVE/ATT&CK/NIST) |
| `learning.jsonl` | `PWN::AI::Agent::Learning` | JSON-per-line | `learning_reset` | task outcome log → success_rate |
| **`mistakes.json`** | **`PWN::AI::Agent::Mistakes`** | **JSON `{sig → entry}`** | **`mistakes_reset`** | **failure fingerprints · cross-session count · fix · `[REPEATING]` · `[REGRESSED]`** |
| `metrics.json` | `PWN::AI::Agent::Metrics` | JSON | `metrics_reset` | per-tool calls · success · avg_duration · last_error |
| `extrospection.json` | `PWN::AI::Agent::Extrospection` | JSON | `extro_reset` | host/net/toolchain/repo/env/**rf**/**web** snapshot + previous baseline + observations[] |
| `extrospection/web/*.png` | `PWN::AI::Agent::Extrospection` | PNG | `rm -rf` | headless-browser screenshots from `probe_web` / `extro_watch` (opt-in) |
| `sessions/*.jsonl` | `PWN::Sessions` | JSON-per-line | `sessions_delete` | full transcript per pwn-ai run |
| `cron/jobs.yml` | `PWN::Cron` | YAML | `cron_remove` | scheduled prompt/ruby/script jobs |
| `cron/log/*.log` | `PWN::Cron` | text | rm | last_run output |
| `agents.yml` | `PWN::AI::Agent::Swarm` | YAML | edit / `agent_spawn` | persona registry |
| `swarm/<id>/bus.jsonl` | `Swarm` | JSON-per-line | rm -rf | append-only multi-agent chat |
| `swarm/<id>/personas.json` | `Swarm` | JSON | rm | persona → session_id map |
| `~/.pwn_history` | Pry | text | rm | REPL input history |

## Back it up

```bash
tar czf pwn-state-$(date +%F).tgz -C "$HOME" .pwn
```

## Start fresh for a new engagement

```ruby
# inside pwn-ai — keeps config & skills, wipes engagement-specific state
extro_reset(confirm: true)     # host snapshot + observations
mistakes_reset(confirm: true)  # failure fingerprints (host-specific errors)
learning_reset(confirm: true)  # task outcomes (optional)
metrics_reset(confirm: true)   # tool telemetry (optional)
```

[← Home](Home.md) · [Configuration](Configuration.md)
