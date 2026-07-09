# Extrospection — World Awareness (on-demand sensing)

`PWN::AI::Agent::Extrospection` is the **outward-facing** counterpart to
[Learning](Skills-Memory-Learning.md). Where Learning/Metrics/Mistakes ask
*"how well did **I** do?"*, Extrospection asks *"what does the **outside world**
say when I need it for a better answer?"*

**Primary intent = sense tools on demand**, not ambient inventory of the local host.

| You need… | Call… |
|---|---|
| Weather / public page content | `extro_watch` / `extro_verify` / TransparentBrowser |
| Song on 101.1 FM (RDS) | **`extro_rf_tune(freq: "101.1")`** → RDS `now_playing` / `station` |
| CVE / Exploit-DB hit | `extro_intel` / `extro_verify(kind: :cve)` |
| Target DOM / TLS drift | `extro_watch(url:)` / `extro_snapshot(sections: [:web])` |

**Secondary** — cheap ambient baseline (`snapshot` / `drift` / `correlate`) so the
agent can distinguish "I called the API wrong" from "the world moved"
(kernel upgrade, dongle unplugged). That baseline must never launch GUI / JVM /
heavy REPL binaries.

![Extrospection engine](diagrams/extrospection-world-awareness.svg)

## Snapshot sections  (`extro_snapshot(sections: […])`)

| Section | Probe | Captures | Auto? |
|---|---|---|---|
| `:host` | `probe_host` | hostname · uname · distro · arch · CPU · mem | ✅ `AUTO_SECTIONS` |
| `:net` | `probe_net` | interfaces · listening ports · default route | ❌ on-demand |
| `:toolchain` | `probe_toolchain` | PATH presence; **safe** bins may get `timeout 2 <bin> --version` | ❌ on-demand |
| `:repo` | `probe_repo` | HEAD · branch · dirty · origin | ✅ `AUTO_SECTIONS` |
| `:env` | `probe_env` | ruby / gem / bundler / PWN version / AI engine | ✅ `AUTO_SECTIONS` |
| **`:rf`** | **`probe_rf`** | **RTL-SDR / HackRF presence · SoapySDR · GQRX sock · Flipper · serial · band-plans** | ❌ on-demand |
| **`:web`** | **`probe_web`** | **Headless render of `web_anchors` (status / title / DOM sha / TLS / screenshot)** | ❌ on-demand |

### `PROBE_BINS` split (why Burp splash used to appear)

```ruby
SAFE_VERSION_BINS  = %w[nmap curl git ruby python3 gcc openssl docker]   # --version OK
PRESENCE_ONLY_BINS = %w[burpsuite zaproxy msfconsole gqrx sqlmap]        # path only — NEVER spawn
RF_BINS            = %w[rtl_sdr rtl_test rtl_433 hackrf_info gqrx dump1090 multimon-ng SoapySDRUtil]
AUTO_SECTIONS      = %i[host repo env]   # what auto_extrospect actually runs
```

`burpsuite` is a Java launcher (`run_java -jar …/burpsuite.jar`). Running it for
`--version` opens the real GUI → splash screen after every pwn-ai turn when
`auto_extrospect` was wiring `probe_toolchain` into the default section set.
**That was the bug.** Presence-only bins + `AUTO_SECTIONS` remove it.

`DEFAULT_WEB_ANCHORS` = NVD CVE 2.0 API, Exploit-DB, upstream `pwn/version.rb`.
Override / extend via `PWN::Env[:ai][:agent][:extrospection][:web][:anchors]`; set
`allow_targets: true` to also fingerprint `PWN::Env[:targets]`.

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
| **`extro_rf_tune`** | **Tune running GQRX + demod + strength + RDS sample → `now_playing` / `station`** | `observations[]` (`category: :rf`, ttl 300s) |
| `extro_correlate` | **Join** introspection ↔ extrospection | — actionable findings |
| `extro_stats` | snapshot age · observation count · drift counts · **rf_devices** · **web_anchors** | — |
| `extro_reset` | Wipe snapshot + observations (new engagement) | — |
| `extro_auto_toggle` | Enable/disable ambient baseline (`AUTO_SECTIONS` only) after every final answer | `PWN::Env[:ai][:agent][:auto_extrospect]` |

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

`probe_rf` is a passive **ear inventory**; `extro_rf_tune` actually **listens** (tune + RDS). `PWN::Plugins::TransparentBrowser` gives Extrospection **eyes**. `extro_verify(claim:)` renders a canonical source *with JavaScript
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

## `extro_rf_tune` — the radio as a sense organ

`probe_rf` is a **passive inventory** (what radios are attached / is GQRX
listening?). `extro_rf_tune` is the **active RF sense organ** — the radio
analogue of `extro_watch` / `extro_verify`. It never launches GQRX (presence-
only bin); it connects to an already-running remote-control socket, tunes,
demodulates, measures strength, and — for FM broadcast — samples RDS:

```text
extro_rf_tune(freq: "101.1")
  → connect GQRX :7356
  → M WFM_ST 200000 ; F 101100000
  → sample RDS for settle_secs (default 8s)
  → { ok, freq, strength_dbfs, station, now_playing, rds:{pi,ps_name,radiotext}, summary }
  → observe(category: :rf, ttl: 300)   # ephemeral — songs change
```

RDS sampling is **`PWN::SDR::Decoder::RDS.sample`** (non-interactive Hash:
`pi` / `ps_name` / `radiotext` / `station`). The TTY spinner
(`Decoder::RDS.decode`) stays the human path used by
`GQRX.init_freq(decoder: :rds)` (default `interactive: true`). Agents and
cron pass `interactive: false` (or just call `.sample` / `extro_rf_tune`).


Frequency parsing is free-form: `"101.1"`, `"101.1 FM"`, `"101.1 MHz"`,
`"101.100.000"`, `101100000`, `"433.92"` all work. Band plan is matched via
`PWN::SDR::FrequencyAllocation` (`fm_radio` → `WFM_ST` + RDS decoder; AM → AM;
etc.). Override with `demodulator_mode:` / `bandwidth:` / `rds:`.

Requires GQRX remote control listening and an SDR attached; returns
`{ok:false, advice:…}` with a concrete recovery hint otherwise. Configure:

```ruby
PWN::Env[:ai][:agent][:extrospection][:rf] = {
  host: '127.0.0.1', port: 7356, settle_secs: 8, ttl: 300
}
```

## `revalidate_memory` — the browser as GC for `PWN::Memory`


`learning_consolidate` only dedupes/truncates; it never asks *"is this still
true?"*. `PWN::AI::Agent::Extrospection.revalidate_memory` walks every
`PWN::Memory` `:fact` containing a CVE / version string / URL, runs `verify()`
on it, and prefixes stale ones with `[UNVERIFIED yyyy-mm-dd]` so the injected
MEMORY block stops calcifying into confidently-wrong priors. Schedule it:

```ruby
cron_create(name: 'memory_revalidate', schedule: '0 4 * * 0',
            ruby: 'PWN::AI::Agent::Extrospection.revalidate_memory')
```

## Configuration

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
extro_snapshot                         # baseline (host/net/toolchain/repo/env/rf; add sections:%i[web] for anchors)
# … recon …
extro_observe(source: 'nmap', target: '10.0.0.5',
              category: 'recon', data: 'OpenSSH 8.2p1 Ubuntu')
extro_observe(source: 'gqrx', target: '433.920MHz',
              category: 'rf', data: 'peak -34.2 dBFS bw=200k FSK — likely garage remote')
extro_rf_tune(freq: '101.1')           # live RDS → now_playing / station (category: :rf)
extro_intel(query: 'OpenSSH 8.2p1', record: true)
extro_watch(url: 'https://target.acme/api/version')       # DOM-hash + screenshot; changed:true on next run
extro_verify(claim: 'CVE-2026-12345 affects OpenSSL 3.2.1')  # → Mistakes/Memory/observe on verdict
# … days later, something breaks …
extro_drift                            # what moved?
extro_correlate                        # why did it break?
```

## Example questions that trigger Extrospection

Natural-language prompts that should fire **outward** sensing (grouped by sense organ).
Location-specific details use **Chicago** as the canonical city so the catalog stays
portable across deployments.

### RF sense organ (`extro_rf_tune` + RF observations)

- “What’s playing on 101.1 right now?”
- “What’s on Q101 / 101.1 FM in Chicago?”
- “Is NOAA weather radio for the Chicago area broadcasting an alert?”
- “Tune 433.92 MHz and report signal strength.”
- “Any ADS-B traffic near Chicago O’Hare (ORD) right now?”
- “Sample RDS on 93.1 for 15 seconds — station name and radiotext?”
- “Is the local Chicago 2 m repeater on 146.x active?”

### Web sense organ (`extro_watch`, `extro_verify`, `snapshot(sections: [:web])`)

- “Did the vendor status page change since last check?”
- “Watch https://status.example.com for DOM changes.”
- “Has the bug-bounty scope page been updated?”
- “What’s the weather in Chicago today?” *(live external page)*
- “Fingerprint that login portal’s generator / title / tech stack.”
- “Screenshot + hash https://target/app/version for drift tracking.”

### Fact-check / claim verification (`extro_verify`)

- “Is CVE-2024-3094 still rated Critical on NVD?”
- “Confirm the latest `pwn` gem on RubyGems is 0.5.x.”
- “Is it true that OpenSSH 9.8p1 is the current stable?”
- “Verify this claim from the advisory against the official page.”
- “Does that docs page actually say what we quoted?”

### Threat intel (`extro_intel` ± `record:true`)

- “Any known exploits for Apache 2.4.58?”
- “Look up CVE-2025-XXXX across NVD / CIRCL / Exploit-DB.”
- “What CVEs hit `libssl` in the last year?”
- “Is there a public PoC for that JetBrains CVE?”
- “Correlate installed nmap version against known CVEs.”

### Host / env / toolchain drift (`extro_snapshot`, `extro_drift`, `extro_stats`)

- “Did the environment change under us since last session?”
- “Take a full extrospection snapshot and show drift.”
- “Is nmap / gqrx / SoapySDR still the version we expect?”
- “What’s listening on this host right now?”
- “Show toolchain + repo HEAD fingerprint.”
- “Why did that tool start failing — world drift or operator error?” → pairs with `extro_correlate`

### Recon memory / observations (`extro_observe`, `extro_observations`)

- “Remember that target X bannered as nginx/1.25.3 on 443.”
- “What recon findings do we have for 10.0.0.5?”
- “List RF observations from today.”
- “Any :web watches that changed this week?”
- “Show intel hits we recorded against this product.”

### Correlation / “am I wrong or did the world move?” (`extro_correlate`)

- “Cross-check recent tool failures against host/toolchain drift.”
- “Did any of our recorded CVEs match installed package versions?”
- “Is that failed shell call explained by missing binaries?”
- “Any refuted claims that should invalidate old memory facts?”

### Operational / lifecycle

- “Enable ambient auto-extrospect after every answer.”
- “Reset extrospection for a new engagement.” *(destructive)*
- “How stale is the current world snapshot?”
- “Toggle auto-extrospect off while we fuzz.”

### Short “trigger” patterns the agent should recognize

| Pattern | Likely tools |
|--------|----------------|
| “What’s on … MHz / FM / station” | `extro_rf_tune` |
| “Did … page change / watch URL” | `extro_watch` |
| “Is it true that… / confirm CVE / latest version” | `extro_verify` |
| “Known vulns / CVE / exploit for…” | `extro_intel` |
| “What changed on this host / drift” | `extro_snapshot` + `extro_drift` |
| “Remember this finding about…” | `extro_observe` |
| “Why did X start failing?” | `extro_correlate` + metrics/mistakes |
| “Weather in Chicago / public page content” | `extro_watch` / TransparentBrowser |

The **inward** half of the loop (Memory · Skills · Learning · Mistakes · Metrics)
has a matching example catalog in [Skills, Memory & Learning](Skills-Memory-Learning.md#example-questions-that-trigger-introspection).

**See also:** [Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Mistakes](Mistakes.md) · [SDR](SDR.md) · [Transparent Browser](Transparent-Browser.md) · [Cron](Cron.md) · [pwn-ai Agent](pwn-ai-Agent.md)

[← Home](Home.md)
