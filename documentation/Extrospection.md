# Extrospection — World Awareness

`PWN::AI::Agent::Extrospection` is the **outward-facing** counterpart to
[Learning](Skills-Memory-Learning.md). Where Learning/Metrics ask *"how well
did **I** do?"*, Extrospection asks *"what does the **world** look like right
now, and has it changed under me?"*

![Extrospection engine](diagrams/extrospection-world-awareness.svg)

## Verbs

| Tool | Does | Persists to |
|---|---|---|
| `extro_snapshot` | Fingerprint host/net/toolchain/repo/env → hash | `extrospection.json` (`snapshot` + rotates `previous`) |
| `extro_drift` | Diff live-vs-stored (or stored-vs-previous) | — returns `{changed, added, removed}` with dotted keys |
| `extro_observe` | Record a recon fact (banner, CVE match, topology note) | `observations[]` |
| `extro_observations` | Query recorded facts by source/category/target/tag | — |
| `extro_intel` | Query NVD / CIRCL / Exploit-DB for keyword or CVE | optional `record: true` → `:intel` observations |
| `extro_correlate` | **Join** introspection ↔ extrospection | — actionable findings |
| `extro_stats` | snapshot age · observation count · drift counts | — |
| `extro_reset` | Wipe snapshot + observations (new engagement) | — |
| `extro_auto_toggle` | Enable/disable auto-snapshot after every final answer | `PWN::Env[:ai][:agent][:auto_extrospect]` |

## `extro_correlate` — the point of the whole thing

```text
(a) Metrics tools with <50 % success   ×  toolchain drift / missing binaries
(b) Learning failures on day X         ×  host/net/repo drift on day X
(c) recorded :intel observations       ×  installed component versions
```

Output tells the agent whether a failure was **its own fault** ("I called the
API wrong") or **the world changed** ("nmap was upgraded and the flag moved")
— and that distinction is written back into MEMORY so the next run doesn't
waste iterations rediscovering it.

## Typical engagement flow

```ruby
extro_reset(confirm: true)             # clean slate for new scope
extro_snapshot                         # baseline
# … recon …
extro_observe(source: 'nmap', target: '10.0.0.5',
              category: 'recon', data: 'OpenSSH 8.2p1 Ubuntu')
extro_intel(query: 'OpenSSH 8.2p1', record: true)
# … days later, something breaks …
extro_drift                            # what moved?
extro_correlate                        # why did it break?
```

**See also:** [Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[pwn-ai Agent](pwn-ai-Agent.md)

[← Home](Home.md)
