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
| Reverse phone / person / FCC ID / patent / IP pivot | **`extro_osint(query:)`** |
| Serial / USB-UART / AT-modem banner | **`extro_serial`** |
| SIP / VoIP / BareSIP status or dial | **`extro_telecomm`** |
| Live capture / pcap summary | **`extro_packet`** |
| OCR image / barcode-QR | **`extro_vision`** |
| Text-to-speech / speech-to-text | **`extro_voice`** |

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
| **`:osint`** | **`probe_osint`** | **Public OSINT feed catalogue · keyed flags (Shodan/Hunter) · whois/dig bins** | ❌ on-demand |
| **`:serial`** | **`probe_serial`** | **`/dev/ttyUSB*` `/dev/ttyACM*` · by-id · minicom/picocom presence** | ❌ on-demand |
| **`:telecomm`** | **`probe_telecomm`** | **BareSIP HTTP · SIP ports · baresip/asterisk/linphone bins** | ❌ on-demand |
| **`:packet`** | **`probe_packet`** | **tshark/tcpdump/tcpreplay · ifaces · cap dir** | ❌ on-demand |
| **`:vision`** | **`probe_vision`** | **tesseract langs · zbarimg · convert/identify** | ❌ on-demand |
| **`:voice`** | **`probe_voice`** | **espeak-ng · festival · whisper · sox · spd-say** | ❌ on-demand |

### `PROBE_BINS` split (why Burp splash used to appear)

```ruby
SAFE_VERSION_BINS  = %w[nmap curl git ruby python3 gcc openssl docker]   # --version OK
PRESENCE_ONLY_BINS = %w[burpsuite zaproxy msfconsole gqrx sqlmap]        # path only — NEVER spawn
RF_BINS            = %w[rtl_sdr rtl_test rtl_433 hackrf_info gqrx dump1090 multimon-ng SoapySDRUtil]
OSINT_BINS         = %w[whois dig host curl jq]
SERIAL_BINS        = %w[minicom picocom screen cu]
TELECOMM_BINS      = %w[baresip asterisk linphone sngrep]
PACKET_BINS        = %w[tshark tcpdump tcpreplay dumpcap]
VISION_BINS        = %w[tesseract zbarimg qrencode convert identify]
VOICE_BINS         = %w[sox espeak-ng espeak festival whisper spd-say arecord aplay]
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
| `extro_observe` | Record a fact — `category:` one of `recon vuln intel target network env` **`rf` `web` `osint` `serial` `telecomm` `packet` `vision` `voice`** `misc` | `observations[]` |
| `extro_observations` | Query recorded facts by source/category/target/tag | — |
| `extro_intel` | Query NVD / CIRCL / Exploit-DB for keyword or CVE | optional `record: true` → `:intel` observations |
| **`extro_watch`** | **Render a URL headless, hash the *rendered* DOM, screenshot, diff vs prior** | `observations[]` (`category: :web`) |
| **`extro_verify`** | **Browser-backed self fact-check of a claim (`:cve` `:version` `:doc` `:generic`) → `:confirmed`/`:refuted`/`:unknown`** | `Mistakes.record` / `observe(:intel)` / `Learning.note_outcome` |
| **`extro_rf_tune`** | **Tune running GQRX + demod + strength + RDS sample → `now_playing` / `station`** | `observations[]` (`category: :rf`, ttl 300s) |
| **`extro_osint`** | **Aggregate public OSINT APIs (phone / IP / domain / FCC ID / patent / person / company / SEC / CourtListener / OTX / URLHaus / openFDA / Nominatim / vital records / Shodan / Hunter / Wayback)** | `observations[]` (`category: :osint`) |
| **`extro_serial`** | **Open serial device · optional payload · drain response · disconnect** | `observations[]` (`category: :serial`) |
| **`extro_telecomm`** | **BareSIP inventory / status / dial / hangup (never launches baresip)** | `observations[]` (`category: :telecomm`) |
| **`extro_packet`** | **Inventory · bounded live capture · pcap summarise (tshark/PacketFu)** | `observations[]` (`category: :packet`) |
| **`extro_vision`** | **OCR (tesseract/RTesseract) · barcode/QR (zbarimg)** | `observations[]` (`category: :vision`) |
| **`extro_voice`** | **TTS (espeak-ng/festival/spd-say) · STT (whisper) · inventory** | `observations[]` (`category: :voice`) |
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

## `extro_osint` — OSINT sense organ

Aggregates as many **public / free** OSINT APIs as practical into one verb.
Optional keyed feeds (Shodan / Hunter) unlock when `SHODAN_API_KEY` /
`HUNTER_API_KEY` or `PWN::Env` keys are present. Every feed is best-effort —
unreachable endpoints return `{error:…}` instead of raising.

### Auto-detected kinds

| Kind | Trigger | Default feeds |
|---|---|---|
| `:ip` | IPv4 / IPv6 | ip · geo · dns · rdap · bgpview · otx · shodan · hackertarget |
| `:geo` | street-like address / geo query | geo · nominatim · ip |
| `:domain` / `:dns` / `:whois` / `:rdap` | FQDN | dns · whois · rdap · crtsh · wayback · otx · urlhaus · urlscan · shodan · hackertarget |
| `:url` | `http(s)://…` | urlscan · otx · urlhaus · wayback |
| `:email` | `a@b.c` | hunter · person · github |
| `:phone` | E.164 / NANP | phone · person |
| `:fcc_id` | `2ABIP-ESP32` style | fcc_id |
| `:patent` | `US10123456` / `patent …` | patent |
| `:person` | `Jane Doe` | person · username · github · vital_records |
| `:username` / `:github` | `@handle` / `gh:` | username · github |
| `:company` | `… Inc.` / `LLC` / `Ltd` | opencorporates · sec_edgar · person · courtlistener |
| `:cik` | 10-digit CIK | sec_edgar · opencorporates |
| `:vital_records` | birth/death/marriage keywords | vital_records · person |
| `:threat` | forced | otx · urlhaus · threatfox |
| `:openfda` | forced | openfda |

### Public feed catalogue (no key unless noted)

| Feed | Sources | Notes |
|---|---|---|
| `:ip` / `:geo` | ip-api.com + `PWN::Plugins::IPInfo` · ipwho.is | ISP/ASN/geo/proxy flags |
| `:dns` | dig + dns.google DoH | A/AAAA/MX/NS/TXT |
| `:whois` | system `whois` | first 4 kB |
| `:rdap` | rdap.org domain/IP bootstrap | JSON |
| `:crtsh` | crt.sh Certificate Transparency | name + issuer + validity |
| `:bgpview` | api.bgpview.io | IP/ASN/search |
| `:shodan` | `PWN::Plugins::Shodan` | **needs** `SHODAN_API_KEY` |
| `:hunter` | `PWN::Plugins::Hunter` | **needs** `HUNTER_API_KEY` |
| `:phone` | NANP/E.164 heuristic + reverse-lookup search targets | country, area-code structure, people-search URLs |
| `:fcc_id` | fccid.io · device.report · fcc.gov OET | grantee/product, MHz excerpts |
| `:patent` | Google Patents HTML + PatentsView API | title, number, assignee, date |
| `:person` | Wikipedia · Wikidata · OpenSanctions + NamUs/FBI/Charley targets | missing-person pivot plan |
| `:username` / `:github` | GitHub · GitLab · Reddit public APIs | profile pivots |
| `:wayback` | archive.org availability + CDX | snapshots |
| `:otx` | AlienVault OTX indicators + passive DNS | IP/domain/url |
| `:urlhaus` | abuse.ch URLHaus host/url API | malware distribution URLs |
| `:threatfox` | abuse.ch ThreatFox IOC search | malware C2 IOCs |
| `:urlscan` | urlscan.io public search | recent scans / screenshots |
| `:hackertarget` | api.hackertarget.com | whois/dns/geoip/headers (rate-limited) |
| `:openfda` | api.fda.gov device 510(k) · drug label · enforcement | FDA public datasets |
| `:nominatim` | OpenStreetMap Nominatim | geocode / reverse address |
| `:opencorporates` | api.opencorporates.com | company search (rate-limited free tier) |
| `:courtlistener` | CourtListener v4 search / people | RECAP opinions + judges |
| `:sec_edgar` | sec.gov company_tickers + EFTS | CIK/ticker/filings |
| `:vital_records` | structured public-record plan | FamilySearch · FindAGrave · CDC W2W · NamUs (live certificates are state-restricted) |

### Examples

```
extro_osint(query: "+13125551212")
  → kind=:phone · feeds.phone = {country_guess, nanp, reverse_lookup_targets}

extro_osint(query: "2ABIP-ESP32", kind: :fcc_id)
  → fccid.io / device.report excerpts + MHz list

extro_osint(query: "US10123456", kind: :patent)
  → google patents titles + patentsview JSON

extro_osint(query: "8.8.8.8")
  → ip-api geo + RDAP + BGPView + OTX pulses

extro_osint(query: "Ada Lovelace", kind: :person)
  → Wikipedia / Wikidata / OpenSanctions + missing-person targets

extro_osint(query: "Acme Robotics LLC", kind: :company)
  → OpenCorporates + SEC EDGAR tickers + CourtListener

extro_osint(query: "birth record Jane Doe", kind: :vital_records)
  → public genealogy + state vital-records index (no closed B2B scrape)
```

Configure:

```ruby
PWN::Env[:ai][:agent][:extrospection][:osint] = {
  ttl: 86_400,
  api_keys: { shodan: '…', hunter: '…' }
}
```


## `extro_serial` — Serial sense organ

Passive inventory via `snapshot(sections: [:serial])` (`/dev/ttyUSB*`,
`/dev/ttyACM*`, `/dev/serial/by-id/*`). The active verb opens a device through
`PWN::Plugins::Serial`, optionally writes a payload (AT command or bytes),
drains the response for `settle_secs`, and **always disconnects** so other
tools can reclaim the bus:

```text
extro_serial(block_dev: "/dev/ttyUSB0", baud: 115200, payload: "ATI\r")
  → { ok, text, hex, line_state, modem_params, bytes }
  → observe(category: :serial)
```

## `extro_telecomm` — SIP / VoIP / PSTN sense organ

Telecomm analogue of `extro_rf_tune`. Talks to a **running** BareSIP HTTP
control socket (never launches it). Actions:

| action | Effect |
|---|---|
| `:inventory` / `:status` | bins · SIP listen ports · BareSIP HTTP reachability · status text |
| `:dial` | require `target:` SIP URI or E.164 — **OPSEC: real call** |
| `:hangup` | hang up active call |

```ruby
PWN::Env[:ai][:agent][:extrospection][:telecomm] = {
  host: '127.0.0.1', port: 8000, ttl: 600
}
```

## `extro_packet` — Packet sense organ

Bounded L2/L3 sensing via `tshark` / `tcpdump` + pcap summarisation through
`PWN::Plugins::Packet` / tshark hierarchy & conversations:

| action | Effect |
|---|---|
| `:inventory` | ifaces + PACKET_BINS presence |
| `:capture` | short capture → `~/.pwn/extrospection/packet/*.pcap` + summary |
| `:summarize_pcap` | parse `path:` pcap (protocol hierarchy, IP conversations) |

Capture is hard-capped (`count` ≤ 200, `timeout` ≤ 60s) so the agent never
hangs mid-turn.

## `extro_vision` — Vision / OCR sense organ

Eyes on the host:

| action | Backend |
|---|---|
| `:ocr` | `PWN::Plugins::OCR` (RTesseract) → `tesseract` CLI fallback |
| `:barcode` | `zbarimg` for barcodes / QR |
| `:inventory` | tesseract langs + vision bins |

```text
extro_vision(file: "/tmp/shot.png", action: :ocr)
  → { text, chars, preview } → observe(category: :vision)
```

## `extro_voice` — Voice (TTS / STT) sense organ

| action | Backend |
|---|---|
| `:tts` | espeak-ng → spd-say → festival (`PWN::Plugins::Voice`) |
| `:stt` | OpenAI whisper binary / `PWN::Plugins::Voice.speech_to_text` |
| `:inventory` | VOICE_BINS presence |

Artefacts land under `~/.pwn/extrospection/voice/`.

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
extro_osint(query: '10.0.0.5', kind: :ip)
extro_osint(query: '2ABIP-ESP32', kind: :fcc_id)
extro_serial(payload: "ATI\r")
extro_packet(action: :capture, filter: 'tcp port 22', count: 20)
extro_vision(file: '/tmp/badge.png', action: :ocr)
extro_voice(action: :tts, text: 'recon complete')
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

### OSINT sense organ (`extro_osint`)

- “Reverse lookup +1 312 555 1212.”
- “Who is the registrant for example.com?”
- “What device is FCC ID 2ABIP-ESP32?”
- “Find patents related to software-defined radio receivers.”
- “Pivot on username @octocat across GitHub/GitLab/Reddit.”
- “Is Jane Doe listed on OpenSanctions / Wikipedia?”
- “CT certs for target.acme via crt.sh.”
- “ASN / BGP neighbours for 1.1.1.1.”
- “Any Wayback snapshots of https://target.acme/login?”

### Serial sense organ (`extro_serial`)

- “What USB serial devices are attached?”
- “Send ATI to the modem on /dev/ttyUSB0 and show the banner.”
- “Talk to the Flipper / RFID reader on ttyACM and dump response hex.”
- “Probe the Arduino console at 115200 8N1.”

### Telecomm sense organ (`extro_telecomm`)

- “Is BareSIP running and what is its status?”
- “List SIP ports listening on this host.”
- “Dial sip:echo@example.com via BareSIP.” *(OPSEC: real call)*
- “Hang up the active VoIP call.”

### Packet sense organ (`extro_packet`)

- “Inventory capture-capable interfaces and tshark/tcpdump.”
- “Capture 20 packets on eth0 for tcp/443 and summarise.”
- “Summarise this pcap: /tmp/eng.pcap.”
- “What IP conversations dominate that capture?”

### Vision / OCR sense organ (`extro_vision`)

- “OCR this screenshot of the login page.”
- “Decode the QR code on /tmp/badge.png.”
- “What languages does tesseract have installed?”

### Voice sense organ (`extro_voice`)

- “Speak ‘engagement complete’ via TTS.”
- “Transcribe /tmp/voicemail.wav.”
- “What TTS/STT engines are available on this host?”

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
| “Reverse phone / FCC ID / patent / whois / person” | `extro_osint` |
| “Serial / AT modem / ttyUSB / Flipper console” | `extro_serial` |
| “SIP / VoIP / BareSIP / dial” | `extro_telecomm` |
| “Capture packets / summarise pcap” | `extro_packet` |
| “OCR / barcode / QR this image” | `extro_vision` |
| “Speak this / transcribe that audio” | `extro_voice` |
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
