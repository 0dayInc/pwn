# Extrospection — World Awareness

`PWN::AI::Agent::Extrospection` is the **outward-facing** counterpart to
[Learning](Skills-Memory-Learning.md). Where Learning/Metrics/Mistakes ask
*"how well did **I** do?"*, Extrospection asks *"what does the **world** look
like right now, and has it changed under me?"*

![Extrospection engine](diagrams/extrospection-world-awareness.svg)

## Snapshot sections  (`extro_snapshot(sections: […])`)

| Section | Probe | Captures |
|---|---|---|
| `:host` | `probe_host` | hostname · uname · distro · arch · CPU · mem |
| `:net` | `probe_net` | interfaces · listening ports · default route |
| `:toolchain` | `probe_toolchain` | `PROBE_BINS` — nmap curl git ruby python3 gcc msfconsole sqlmap burpsuite zaproxy openssl docker **+ RF_BINS** |
| `:repo` | `probe_repo` | HEAD · branch · dirty · origin |
| `:env` | `probe_env` | ruby / gem / bundler / PWN version |
| **`:rf`** | **`probe_rf`** | **RTL-SDR / HackRF presence · SoapySDR devices · GQRX socket (127.0.0.1:7356) · Flipper serial · `/dev/tty{USB,ACM}*` · band-plan count** |

`RF_BINS = %w[rtl_sdr rtl_test rtl_433 hackrf_info gqrx dump1090 multimon-ng SoapySDRUtil]`
— these are also merged into `PROBE_BINS` so RF-toolchain drift shows up under
`toolchain.*` diff keys.

## Verbs

| Tool | Does | Persists to |
|---|---|---|
| `extro_snapshot` | Fingerprint host/net/toolchain/repo/env/**rf** → hash | `extrospection.json` (`snapshot` + rotates `previous`) |
| `extro_drift` | Diff live-vs-stored (or stored-vs-previous) | — returns `{changed, added, removed}` with dotted keys |
| `extro_observe` | Record a fact — `category:` one of `recon vuln intel target network env` **`rf`** `misc` | `observations[]` |
| `extro_observations` | Query recorded facts by source/category/target/tag | — |
| `extro_intel` | Query NVD / CIRCL / Exploit-DB for keyword or CVE | optional `record: true` → `:intel` observations |
| `extro_correlate` | **Join** introspection ↔ extrospection | — actionable findings |
| `extro_stats` | snapshot age · observation count · drift counts · **rf_devices** | — |
| `extro_reset` | Wipe snapshot + observations (new engagement) | — |
| `extro_auto_toggle` | Enable/disable auto-snapshot after every final answer | `PWN::Env[:ai][:agent][:auto_extrospect]` |

## `extro_correlate` — the point of the whole thing

```text
(a) Metrics tools with <50 % success   ×  toolchain drift / missing binaries
(b) Learning failures on day X         ×  host/net/repo drift on day X
(c) recorded :intel observations       ×  installed component versions
(d) recorded :rf observations          ×  missing SDR hardware / RF_BINS
```

Output tells the agent whether a failure was **its own fault** ("I called the
API wrong" → belongs in [Mistakes](Mistakes.md)) or **the world changed**
("nmap was upgraded and the flag moved", "the HackRF was unplugged") — and
that distinction is written back into MEMORY so the next run doesn't waste
iterations rediscovering it.

## Typical engagement flow

```ruby
extro_reset(confirm: true)             # clean slate for new scope
extro_snapshot                         # baseline (all six sections)
# … recon …
extro_observe(source: 'nmap', target: '10.0.0.5',
              category: 'recon', data: 'OpenSSH 8.2p1 Ubuntu')
extro_observe(source: 'gqrx', target: '433.920MHz',
              category: 'rf', data: 'peak -34.2 dBFS bw=200k FSK — likely garage remote')
extro_intel(query: 'OpenSSH 8.2p1', record: true)
# … days later, something breaks …
extro_drift                            # what moved?
extro_correlate                        # why did it break?
```

**See also:** [Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Mistakes](Mistakes.md) · [SDR](SDR.md) · [pwn-ai Agent](pwn-ai-Agent.md)

[← Home](Home.md)
