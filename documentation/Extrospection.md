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
| **`:web`** *(opt-in)* | **`probe_web`** | **Renders `web_anchors` via `PWN::Plugins::TransparentBrowser` (`:headless`) — HTTP status · final URL · `<title>` · meta[generator] · `Server` · SHA-256 of *rendered* DOM text · TLS cert fp / notAfter · optional screenshot → `~/.pwn/extrospection/web/<host>.png`** |

`RF_BINS = %w[rtl_sdr rtl_test rtl_433 hackrf_info gqrx dump1090 multimon-ng SoapySDRUtil]`
— these are also merged into `PROBE_BINS` so RF-toolchain drift shows up under
`toolchain.*` diff keys.

`DEFAULT_WEB_ANCHORS` = NVD CVE 2.0 API, Exploit-DB, upstream `pwn/version.rb`.
Override / extend via `PWN::Env[:ai][:agent][:extrospection][:web][:anchors]`; set
`allow_targets: true` to also fingerprint `PWN::Env[:targets]`. **`:web` is never
run by `auto_extrospect`** — a headless browser is ~1–3 s cold vs ~50 ms for
`probe_host`, so it's opt-in (`extro_snapshot(sections: %i[web])`).

## Verbs

| Tool | Does | Persists to |
|---|---|---|
| `extro_snapshot` | Fingerprint host/net/toolchain/repo/env/**rf**/*web* → hash | `extrospection.json` (`snapshot` + rotates `previous`) |
| `extro_drift` | Diff live-vs-stored (or stored-vs-previous) | — returns `{changed, added, removed}` with dotted keys |
| `extro_observe` | Record a fact — `category:` one of `recon vuln intel target network env` **`rf` `web`** `misc` | `observations[]` |
| `extro_observations` | Query recorded facts by source/category/target/tag | — |
| `extro_intel` | Query NVD / CIRCL / Exploit-DB for keyword or CVE | optional `record: true` → `:intel` observations |
| **`extro_watch`** | **Render a URL headless, hash the *rendered* DOM, screenshot, diff vs prior** | `observations[]` (`category: :web`) |
| **`extro_verify`** | **Browser-backed self fact-check of a claim (`:cve` `:version` `:doc` `:generic`) → `:confirmed`/`:refuted`/`:unknown`** | `Mistakes.record` / `observe(:intel)` / `Learning.note_outcome` |
| `extro_correlate` | **Join** introspection ↔ extrospection | — actionable findings |
| `extro_stats` | snapshot age · observation count · drift counts · **rf_devices** · **web_anchors** | — |
| `extro_reset` | Wipe snapshot + observations (new engagement) | — |
| `extro_auto_toggle` | Enable/disable auto-snapshot after every final answer | `PWN::Env[:ai][:agent][:auto_extrospect]` |

## `extro_correlate` — the point of the whole thing

```text
(a) Metrics tools with <50 % success   ×  toolchain drift / missing binaries
(b) Learning failures on day X         ×  host/net/repo drift on day X
(c) recorded :intel observations       ×  installed component versions
(d) recorded :rf observations          ×  missing SDR hardware / RF_BINS
(e) recorded :web DOM drift on target  ×  Learning failures citing that host
(f) extro_verify :refuted claims       ×  stale PWN::Memory :fact entries
(g) :intel obs whose feed anchor is    ×  probe_web-unreachable → downgrade weight
```

Output tells the agent whether a failure was **its own fault** ("I called the
API wrong" → belongs in [Mistakes](Mistakes.md)) or **the world changed**
("nmap was upgraded and the flag moved", "the HackRF was unplugged") — and
that distinction is written back into MEMORY so the next run doesn't waste
iterations rediscovering it.

## `extro_verify` — proactive fact-checking (the browser as a sense organ)

`probe_rf` gave Extrospection **ears**; `PWN::Plugins::TransparentBrowser` gives
it **eyes**. `extro_verify(claim:)` renders a canonical source *with JavaScript
executed* and returns a verdict:

| `kind:` | Canonical source (rendered headless) | Verdict logic |
|---|---|---|
| `:cve` | `nvd.nist.gov/vuln/detail/<id>` + `cve.org/CVERecord?id=` | CVE exists? affected-product string overlaps claimed product/version? |
| `:version` | rubygems.org / PyPI / GitHub search | claimed "latest is X" vs scraped latest |
| `:doc` | the URL the model cited | 200? title/body contains ≥ 40 % of the quoted-snippet tokens (fuzzy)? |
| `:generic` | DuckDuckGo HTML (proxy-able, no API key) | ≥ 50 % token overlap in top result snippets |

```text
                  ┌── :refuted  → Mistakes.record(tool:'assumption', …)  → KNOWN MISTAKES block ∀ future runs
extro_verify ─────┼── :confirmed→ observe(category::intel, ttl:30d)      → EXTROSPECTION block, freshness-bound
                  └── :unknown  → Learning.note_outcome(tags:[needs_human])
```

This adds a **proactive** trigger to the negative-feedback loop: today
`Mistakes.record` fires only *reactively* (a tool blew up, or a human said
"that's wrong"). `extro_verify` lets the agent catch itself being wrong about
the world **before** a human does. `commit: false` returns the verdict without
side-effects.

### `revalidate_memory` — the browser as GC for `PWN::Memory`

`learning_consolidate` only dedupes/truncates; it never asks *"is this still
true?"*. `PWN::AI::Agent::Extrospection.revalidate_memory` walks every
`PWN::Memory` `:fact` containing a CVE / version string / URL, runs `verify()`
on it, and prefixes stale ones with `[UNVERIFIED yyyy-mm-dd]` so the injected
MEMORY block stops calcifying into confidently-wrong priors. Schedule it:

```ruby
cron_create(name: 'memory_revalidate', schedule: '0 4 * * 0',
            ruby: 'PWN::AI::Agent::Extrospection.revalidate_memory')
```

### Configuration

```ruby
PWN::Env[:ai][:agent][:extrospection][:web] = {
  anchors:          ['https://target.acme/api/version', …],  # else DEFAULT_WEB_ANCHORS
  proxy:            'tor',      # or 'http://127.0.0.1:8080' (Burp) — honoured by verify/watch/probe_web
  max_anchors:      8,
  per_page_timeout: 15,
  screenshot:       false,      # → ~/.pwn/extrospection/web/<host>.png
  allow_targets:    false       # OPSEC: also fingerprint PWN::Env[:targets] (active recon!)
}
```


## Typical engagement flow

```ruby
extro_reset(confirm: true)             # clean slate for new scope
extro_snapshot                         # baseline (six local sections; add sections:%i[web] for anchors)
# … recon …
extro_observe(source: 'nmap', target: '10.0.0.5',
              category: 'recon', data: 'OpenSSH 8.2p1 Ubuntu')
extro_observe(source: 'gqrx', target: '433.920MHz',
              category: 'rf', data: 'peak -34.2 dBFS bw=200k FSK — likely garage remote')
extro_intel(query: 'OpenSSH 8.2p1', record: true)
extro_watch(url: 'https://target.acme/api/version')       # DOM-hash + screenshot; changed:true on next run
extro_verify(claim: 'CVE-2026-12345 affects OpenSSL 3.2.1')  # → Mistakes/Memory/observe on verdict
# … days later, something breaks …
extro_drift                            # what moved?
extro_correlate                        # why did it break?
```

**See also:** [Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Mistakes](Mistakes.md) · [SDR](SDR.md) · [Transparent Browser](Transparent-Browser.md) · [Cron](Cron.md) · [pwn-ai Agent](pwn-ai-Agent.md)

[← Home](Home.md)
