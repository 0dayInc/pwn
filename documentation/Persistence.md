# `~/.pwn/` - Persistence Map

Every byte PWN remembers between processes lives here.

![~/.pwn map](diagrams/persistence-filesystem.svg)

| Path | Owner | Format | Reset tool | Purpose |
|---|---|---|---|---|
| `pwn.yaml` | `PWN::Config` · `PWN::Plugins::Vault` | AES-encrypted YAML | `pwn-vault` | engines, keys, agent options |
| `pwn.yaml.decryptor` | `PWN::Plugins::Vault` | key/IV | - | decrypts `pwn.yaml` (or set `PWN_DECRYPTOR_KEY`/`_IV`) |
| **`.schema`** | **`PWN::Migrate`** | JSON `{schema:,pwn_version:,at:}` | `pwn setup --migrate` | **schema stamp - drives the one-line drift warning on launch** |
| `memory.json` | `PWN::Memory` | JSON array | `memory_clear` | facts · prefs · lessons · env - injected into every prompt |
| `memory.idx` | `PWN::MemoryIndex` | JSON `{key → {sha,vec}}` | `PWN::MemoryIndex.reset` | local embedding index over `memory.json` - powers **relevance-ranked** MEMORY injection (incremental; only re-embeds changed entries) |
| `skills/<name>/SKILL.md` | `PWN::Config.load_skills` | **[agentskills.io](https://agentskills.io) spec** - `name`+`description` YAML front-matter | `skill_delete` | reusable procedures + `metadata.references:` (CWE/CVE/ATT&CK/NIST). Legacy flat `skills/*.md` auto-migrated by `skill_migrate_legacy` / `pwn setup --migrate --fix`. |
| `learning.jsonl` | `PWN::AI::Agent::Learning` | JSON-per-line | `learning_reset` | task outcome log → success_rate |
| **`preferences.jsonl`** | **`PWN::AI::Agent::Reward`** | JSON-per-line `{prompt,rejected,chosen,source}` | `rm` | **DPO/KTO/ORPO preference-pair ledger - user_correction · mistakes_resolve · counterfactual · critic · curriculum** |
| **`mistakes.json`** | **`PWN::AI::Agent::Mistakes`** | **JSON `{sig → entry}`** | **`mistakes_reset`** | **failure fingerprints · cross-session count · fix · `[REPEATING]` · `[REGRESSED]`** |
| `metrics.json` | `PWN::AI::Agent::Metrics` | JSON | `metrics_reset` | per-tool calls · success · avg_duration · last_error · **per-engine** sub-buckets · calibration |
| `reward_sentinel.json` | `PWN::AI::Agent::Reward` | JSON | `rm` | R3 - proxy vs judge vs user-correction gap history |
| `extrospection.json` | `PWN::AI::Agent::Extrospection` | JSON | `extro_reset` | host/net/toolchain/repo/env/**rf**/**web**/osint/serial/telecomm/packet/vision/voice snapshot + previous baseline + observations[] |
| `extrospection/web/*.png` | `Extrospection` | PNG | `rm -rf` | headless-browser screenshots from `probe_web` / `extro_watch` (opt-in) |
| `extrospection/packet/*.pcap` | `Extrospection` | pcap | `rm -rf` | bounded captures from `extro_packet(action: :capture)` |
| `extrospection/voice/*` | `Extrospection` | wav / txt | `rm -rf` | TTS/STT artifacts from `extro_voice` |
| `sessions/*.jsonl` | `PWN::Sessions` | JSON-per-line | `sessions_delete` | full transcript per pwn-ai run (with per-step `step_reward` from `Reward.prm`) |
| `cron/jobs.yml` | `PWN::Cron` | YAML | `cron_remove` | scheduled prompt/ruby/script jobs (**seeded** with `curriculum_practice_nightly` + `curriculum_train_weekly`) |
| `cron/log/*.log` | `PWN::Cron` | text | rm | last_run output |
| `agents.yml` | `PWN::AI::Agent::Swarm` | YAML | edit / `agent_spawn` | persona registry |
| `swarm/<id>/bus.jsonl` | `Swarm` | JSON-per-line | rm -rf | append-only multi-agent chat |
| `swarm/<id>/personas.json` | `Swarm` | JSON | rm | persona → session_id map |
| `curriculum/` | `PWN::AI::Agent::Curriculum` | JSONL | rm -rf | S1 self-play reproducers · W2 A/B eval sets |
| `finetune/*.jsonl` | `Learning.export_finetune` · `Reward.export_dpo` | ShareGPT / OpenAI / DPO JSONL | `rm` | supervised + preference datasets - feed to a LoRA over the local model |
| `backup/<ts>/` | `PWN::Migrate` | tree copy | rm -rf | timestamped snapshot taken before every `--migrate --fix` |
| `quarantine/` | `PWN::Migrate` | quarantined originals | rm -rf | corrupt/incompatible state files moved aside so the owner re-seeds |
| `~/.pwn_history` | Pry | text | rm | REPL input history |

## Verify / repair the whole tree

```bash
pwn setup --migrate            # per-file compatibility report + apply schema migrations
pwn setup --migrate --fix      # + autofix (backup → quarantine/repair → vault backfill)
```

```ruby
PWN::Migrate.status            # machine-readable rows
PWN::Migrate.needed?           # ~/.pwn/.schema older than PWN::Migrate::SCHEMA_VERSION ?
```

See [Installation § Upgrading](Installation.md#upgrading--pwn-state-migration-pwnmigrate)
for the full `PWN::Migrate` API.

## Back it up

```bash
tar czf pwn-state-$(date +%F).tgz -C "$HOME" .pwn
```

`pwn setup --migrate --fix` also writes one automatically to
`~/.pwn/backup/<timestamp>/` before touching anything.

## Start fresh for a new engagement

```ruby
# inside pwn-ai - keeps config & skills, wipes engagement-specific state
extro_reset(confirm: true)     # host snapshot + observations
mistakes_reset(confirm: true)  # failure fingerprints (host-specific errors)
learning_reset(confirm: true)  # task outcomes (optional)
metrics_reset(confirm: true)   # tool telemetry (optional)
```

[← Home](Home.md) · [Configuration](Configuration.md) · [Installation](Installation.md)
