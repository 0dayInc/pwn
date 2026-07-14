# Extrospection - World Awareness (on-demand sensing)

`PWN::AI::Agent::Extrospection` is the **outward-facing** counterpart to
[Learning](Skills-Memory-Learning.md). Where Learning/Metrics/Mistakes ask
*"how well did **I** do?"*, Extrospection asks *"what does the **outside world**
say when I need it for a better answer?"*

**Primary intent = sense tools on demand**, not ambient inventory of the local host.

| You need... | Call... |
|---|---|
| Weather / public page content | `extro_watch` / `extro_verify` / TransparentBrowser |
| Song on 101.1 FM (RDS) | **`extro_rf_tune(freq: "101.1")`** → RDS `now_playing` / `station` |
| CVE / Exploit-DB hit | `extro_intel` / `extro_verify(kind: :cve)` |
| Target DOM / TLS drift | `extro_watch(url:)` / `extro_snapshot(sections: [:web])` |
| Reverse phone / person / @handle sweep / FCC ID / patent / IP pivot | **`extro_osint(query:)`** |
| Serial / USB-UART / AT-modem banner | **`extro_serial`** |
| SIP / VoIP / BareSIP status or dial | **`extro_telecomm`** |
| Live capture / pcap summary | **`extro_packet`** |
| OCR image / barcode-QR | **`extro_vision`** |
| Text-to-speech / speech-to-text | **`extro_voice`** |

**Secondary** - cheap ambient baseline (`snapshot` / `drift` / `correlate`) so the
agent can distinguish "I called the API wrong" from "the world moved"
(kernel upgrade, dongle unplugged). That baseline must never launch GUI / JVM /
heavy REPL binaries.

![Extrospection engine](diagrams/extrospection-world-awareness.svg)

## Snapshot sections  (`extro_snapshot(sections: [...])`)

| Section | Probe | Captures | Auto? |
|---|---|---|---|
| `:host` | `probe_host` | hostname · uname · distro · arch · CPU · mem | ✅ `AUTO_SECTIONS` |
| `:net` | `probe_net` | interfaces · listening ports · default route | ❌ on-demand |
| `:toolchain` | `probe_toolchain` | PATH presence; **safe** bins may get `timeout 2 <bin> --version` | ❌ on-demand |
| `:repo` | `probe_repo` | HEAD · branch · dirty · origin | ✅ `AUTO_SECTIONS` |
| `:env` | `probe_env` | ruby / gem / bundler / PWN version / AI engine | ✅ `AUTO_SECTIONS` |
| **`:rf`** | **`probe_rf`** | **RTL-SDR / HackRF presence · SoapySDR · GQRX sock · Flipper · serial · band-plans** | ❌ on-demand |
| **`:web`** | **`probe_web`** | **Headless render of `web_anchors` (status / title / DOM sha / TLS / screenshot)** | ❌ on-demand |
| **`:osint`** | **`probe_osint`** | **Public OSINT feed catalog · keyed flags (Shodan/Hunter) · whois/dig bins** | ❌ on-demand |
| **`:serial`** | **`probe_serial`** | **`/dev/ttyUSB*` `/dev/ttyACM*` · by-id · minicom/picocom presence** | ❌ on-demand |
| **`:telecomm`** | **`probe_telecomm`** | **BareSIP HTTP · SIP ports · baresip/asterisk/linphone bins** | ❌ on-demand |
| **`:packet`** | **`probe_packet`** | **tshark/tcpdump/tcpreplay · ifaces · cap dir** | ❌ on-demand |
| **`:vision`** | **`probe_vision`** | **tesseract langs · zbarimg · convert/identify** | ❌ on-demand |
| **`:voice`** | **`probe_voice`** | **espeak-ng · festival · whisper · sox · spd-say** | ❌ on-demand |

### `PROBE_BINS` split (why Burp splash used to appear)

```ruby
SAFE_VERSION_BINS  = %w[nmap curl git ruby python3 gcc openssl docker]   # --version OK
PRESENCE_ONLY_BINS = %w[burpsuite zaproxy msfconsole gqrx sqlmap]        # path only - NEVER spawn
RF_BINS            = %w[rtl_sdr rtl_test rtl_433 hackrf_info gqrx dump1090 multimon-ng SoapySDRUtil]
OSINT_BINS         = %w[whois dig host curl jq]
SERIAL_BINS        = %w[minicom picocom screen cu]
TELECOMM_BINS      = %w[baresip asterisk linphone sngrep]
PACKET_BINS        = %w[tshark tcpdump tcpreplay dumpcap]
VISION_BINS        = %w[tesseract zbarimg qrencode convert identify]
VOICE_BINS         = %w[sox espeak-ng espeak festival whisper spd-say arecord aplay]
AUTO_SECTIONS      = %i[host repo env]   # what auto_extrospect actually runs
```

`burpsuite` is a Java launcher (`run_java -jar .../burpsuite.jar`). Running it for
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
| `extro_drift` | Diff live-vs-stored (or stored-vs-previous) | - returns `{changed, added, removed}` with dotted keys |
| `extro_observe` | Record a fact - `category:` one of `recon vuln intel target network env` **`rf` `web` `osint` `serial` `telecomm` `packet` `vision` `voice`** `misc` | `observations[]` |
| `extro_observations` | Query recorded facts by source/category/target/tag | - |
| `extro_intel` | Query NVD / CIRCL / Exploit-DB for keyword or CVE | optional `record: true` → `:intel` observations |
| **`extro_watch`** | **Render a URL headless, hash the *rendered* DOM, screenshot, diff vs prior** | `observations[]` (`category: :web`) |
| **`extro_verify`** | **Browser-backed self fact-check of a claim (`:cve` `:version` `:doc` `:generic`) → `:confirmed`/`:refuted`/`:unknown`** | `Mistakes.record` / `observe(:intel)` / `Learning.note_outcome` |
| **`extro_rf_tune`** | **Tune running GQRX + demod + strength + RDS sample → `now_playing` / `station`** | `observations[]` (`category: :rf`, ttl 300s) |
| **`extro_osint`** | **Aggregate public OSINT APIs (phone / IP / domain / FCC ID / patent / VIN / MAC / callsign / person / company / SEC / CourtListener / Federal Register / UK Police / OTX / URLHaus / openFDA / NPPES / Nominatim / EPSS / CISA KEV / Microlink / vital records / Shodan / Hunter / AbuseIPDB / VT / HIBP / Wayback) + social/identity feeds (Keybase / Gravatar / Mastodon / Bluesky / HN / StackExchange / npm / PyPI / RubyGems / crates / DockerHub / Codeberg / Steam / Telegram + ~100-site presence sweep) + local-tool bridges (theHarvester / spiderfoot / amass / recon-ng)** | `observations[]` (`category: :osint`) |
| **`extro_serial`** | **Open serial device · optional payload · drain response · disconnect** | `observations[]` (`category: :serial`) |
| **`extro_telecomm`** | **BareSIP inventory / status / dial / hangup (never launches baresip)** | `observations[]` (`category: :telecomm`) |
| **`extro_packet`** | **Inventory · bounded live capture · pcap summarise (tshark/PacketFu)** | `observations[]` (`category: :packet`) |
| **`extro_vision`** | **OCR (tesseract/RTesseract) · barcode/QR (zbarimg)** | `observations[]` (`category: :vision`) |
| **`extro_voice`** | **TTS (espeak-ng/festival/spd-say) · STT (whisper) · inventory** | `observations[]` (`category: :voice`) |
| `extro_correlate` | **Join** introspection ↔ extrospection | - actionable findings |
| `extro_stats` | snapshot age · observation count · drift counts · **rf_devices** · **web_anchors** | - |
| `extro_reset` | Wipe snapshot + observations (new engagement) | - |
| `extro_auto_toggle` | Enable/disable ambient baseline (`AUTO_SECTIONS` only) after every final answer | `PWN::Env[:ai][:agent][:auto_extrospect]` |

## `extro_correlate` - the point of the whole thing

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
("nmap was upgraded and the flag moved", "the HackRF was unplugged") - and
that distinction is written back into MEMORY so the next run doesn't waste
iterations rediscovering it.

## `extro_verify` - proactive fact-checking (the browser as a sense organ)

`probe_rf` is a passive **ear inventory**; `extro_rf_tune` actually **listens** (tune + RDS). `PWN::Plugins::TransparentBrowser` gives Extrospection **eyes**. `extro_verify(claim:)` renders a canonical source *with JavaScript
executed* and returns a verdict:

| `kind:` | Canonical source (rendered headless) | Verdict logic |
|---|---|---|
| `:cve` | `nvd.nist.gov/vuln/detail/<id>` + `cve.org/CVERecord?id=` | CVE exists? affected-product string overlaps claimed product/version? |
| `:version` | rubygems.org / PyPI / GitHub search | claimed "latest is X" vs scraped latest |
| `:doc` | the URL the model cited | 200? title/body contains ≥ 40 % of the quoted-snippet tokens (fuzzy)? |
| `:generic` | DuckDuckGo HTML (proxy-able, no API key) | ≥ 50 % token overlap in top result snippets |

```text
                  ┌── :refuted  → Mistakes.record(tool:'assumption', ...)  → KNOWN MISTAKES block ∀ future runs
extro_verify ─────┼── :confirmed→ observe(category::intel, ttl:30d)      → EXTROSPECTION block, freshness-bound
                  └── :unknown  → Learning.note_outcome(tags:[needs_human])
```

This adds a **proactive** trigger to the negative-feedback loop: today
`Mistakes.record` fires only *reactively* (a tool blew up, or a human said
"that's wrong"). `extro_verify` lets the agent catch itself being wrong about
the world **before** a human does. `commit: false` returns the verdict without
side-effects.

## `extro_rf_tune` - the radio as a sense organ

`probe_rf` is a **passive inventory** (what radios are attached / is GQRX
listening?). `extro_rf_tune` is the **active RF sense organ** - the radio
analogue of `extro_watch` / `extro_verify`. It never launches GQRX (presence-
only bin); it connects to an already-running remote-control socket, tunes,
demodulates, measures strength, and - for FM broadcast - samples RDS:

```text
extro_rf_tune(freq: "101.1")
  → connect GQRX :7356
  → M WFM_ST 200000 ; F 101100000
  → sample RDS for settle_secs (default 8s)
  → { ok, freq, strength_dbfs, station, now_playing, rds:{pi,ps_name,radiotext}, summary }
  → observe(category: :rf, ttl: 300)   # ephemeral - songs change
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
`{ok:false, advice:...}` with a concrete recovery hint otherwise. Configure:

```ruby
PWN::Env[:ai][:agent][:extrospection][:rf] = {
  host: '127.0.0.1', port: 7356, settle_secs: 8, ttl: 300
}
```

## `extro_osint` - OSINT sense organ

Aggregates as many **public / free** OSINT APIs as practical into one verb.
Optional keyed feeds (Shodan / Hunter) unlock when `SHODAN_API_KEY` /
`HUNTER_API_KEY` or `PWN::Env` keys are present. Every feed is best-effort -
unreachable endpoints return `{error:...}` instead of raising.

### Auto-detected kinds

| Kind | Trigger | Default feeds |
|---|---|---|
| `:ip` | IPv4 / IPv6 | ip · geo · ipapi_is · iplocate · ipwhois · dns · rdap · bgpview · otx · abuseipdb · greynoise · shodan · hackertarget |
| `:geo` | street-like address / geo query | geo · nominatim · ip |
| `:domain` / `:dns` / `:whois` / `:rdap` | FQDN | dns · whois · rdap · crtsh · certspotter · wayback · otx · urlhaus · urlscan · shodan · securitytrails · hackertarget · theharvester · amass |
| `:url` | `http(s)://...` | urlscan · otx · urlhaus · wayback · microlink · virustotal |
| `:email` | `a@b.c` | hunter · person · github · haveibeenpwned · gravatar · keybase |
| `:phone` | E.164 / NANP | phone · person |
| `:fcc_id` | `2ABIP-ESP32` style | fcc_id |
| `:patent` | `US10123456` / `patent ...` | patent |
| `:person` | `Jane Doe` | person · username · github · open_sanctions · agify · genderize · nationalize · vital_records |
| `:username` / `:github` | bare `handle` / `gh:` | username · github · keybase · hackernews · social_sweep |
| `:social` | `@handle` / `@user@instance` (Fediverse) | keybase · gravatar · mastodon · bluesky · hackernews · stackexchange · npm · pypi · rubygems · crates · dockerhub · codeberg · sourcehut · chesscom · lichess · steam · telegram · github · social_sweep |
| `:company` | `... Inc.` / `LLC` / `Ltd` | opencorporates · sec_edgar · federal_register · person · courtlistener |
| `:cik` | 10-digit CIK | sec_edgar · opencorporates |
| `:vital_records` | birth/death/marriage keywords | vital_records · person |
| `:threat` | forced | otx · urlhaus · threatfox · abuseipdb · greynoise · virustotal · epss · cisa_kev |
| `:openfda` | forced | openfda |
| `:vin` | 17-char ISO 3779 VIN | nhtsa (NHTSA vPIC / `PWN::Plugins::VIN`) |
| `:mac` | `00:11:22:33:44:55` / bare hex / Cisco form | mac_vendor |
| `:callsign` | amateur radio e.g. `W1AW` | callook |
| `:npi` | `NPI 1679576722` (prefixed) | nppes |
| `:cve` | `CVE-YYYY-NNNN` | epss · cisa_kev |

### Public feed catalog (no key unless noted)

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
| `:username` / `:github` | GitHub · GitLab · Reddit public APIs | legacy 3-platform profile pivots (kept for back-compat) |
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
| `:ipapi_is` | api.ipapi.is | IP company/ASN/hosting/proxy/crawler flags (free) |
| `:iplocate` | iplocate.io | IP geo + threat (proxy/VPN/hosting) |
| `:ipwhois` | ipwho.is | Free IP geo / connection / timezone |
| `:abuseipdb` | api.abuseipdb.com | IP reputation - **needs** `ABUSEIPDB_API_KEY` |
| `:virustotal` | virustotal.com API v3 | URL/domain/IP analysis - **needs** `VIRUSTOTAL_API_KEY` |
| `:greynoise` | greynoise.io community / v2 | Internet scanner noise (community free; key upgrades) |
| `:certspotter` | api.certspotter.com | Certificate Transparency issuances |
| `:epss` | api.first.org/data/v1/epss | Exploit Prediction Scoring System for a CVE |
| `:cisa_kev` | CISA Known Exploited Vulnerabilities catalog | KEV membership / ransomware flag |
| `:nhtsa` | vpic.nhtsa.dot.gov + `PWN::Plugins::VIN` | VIN decode / make-model |
| `:nppes` | npiregistry.cms.hhs.gov | US healthcare NPI provider lookup |
| `:federal_register` | federalregister.gov API | US Federal Register document search |
| `:uk_police` | data.police.uk | UK street-level crime / force catalog |
| `:callook` | callook.info | US amateur-radio callsign (FCC ULS) |
| `:mac_vendor` | maclookup.app · macvendors.com | MAC OUI → vendor |
| `:universities` | universities.hipolabs.com | University name / domain / country |
| `:microlink` | api.microlink.io | Link unfurl (OG title/desc/image) |
| `:agify` / `:genderize` / `:nationalize` | agify.io · genderize.io · nationalize.io | First-name age/gender/nationality estimates |
| `:haveibeenpwned` | haveibeenpwned.com v3 | Breach membership - **needs** `HIBP_API_KEY` |
| `:securitytrails` | api.securitytrails.com | Domain DNS history - **needs** `SECURITYTRAILS_API_KEY` |
| `:keybase` | keybase.io lookup API | **crypto-proven** cross-links (Twitter/GitHub/DNS/PGP) → highest-confidence pivots |
| `:gravatar` | gravatar.com profile JSON | email → md5 → username, verified accounts, bio, urls |
| `:mastodon` | `<instance>/api/v1/accounts/lookup` + WebFinger | Fediverse identity; instance defaults to `mastodon.social` |
| `:bluesky` | public.api.bsky.app `getProfile` | DID, handle, followers, bio |
| `:hackernews` | hn.algolia.com users + submissions | karma, about, recent posts |
| `:stackexchange` | api.stackexchange.com users?inname= | rep, location, website |
| `:npm` | registry.npmjs.org user + maintainer search | packages, email, GitHub/Twitter |
| `:pypi` | pypi.org/user/ (HTML) | packages maintained |
| `:rubygems` | rubygems.org owners/gems API | gems, downloads, homepage |
| `:crates` | crates.io users API | login, name, url |
| `:dockerhub` | hub.docker.com v2 users + repos | full_name, company, images |
| `:codeberg` | codeberg.org Gitea API | login, full_name, website, location |
| `:sourcehut` | sr.ht/~user (presence) | HTTP presence check |
| `:chesscom` / `:lichess` | api.chess.com · lichess.org/api | real name, country, timezone leak |
| `:steam` | steamcommunity.com XML / ISteamUser | vanity → SteamID64, persona; **key upgrades** to ISteamUser |
| `:telegram` | t.me/<user> og:meta scrape | display name, description (200 always → body-heuristic) |
| `:social_sweep` | `etc/osint/social_sites.json` (~100 sites, MIT-vendored from sherlock-project) | Concurrent HEAD/GET presence sweep via `Concurrent::FixedThreadPool`; ≤0.5 confidence (soft-404s possible) |
| `:theharvester` | **local bin** `theHarvester -b <sources> -f json` | domain → hosts, emails, IPs, ASNs (passive sources only) |
| `:amass` | **local bin** `amass enum -passive -json` | domain → subdomains + resolved addresses |
| `:spiderfoot` | **local bin** `spiderfoot -s <t> -m <mods> -o json -q` | headless CLI events grouped by type; web UI never launched |
| `:reconng` | **local bin** `recon-ng -r <resource>` | domain → hosts via hackertarget + CT modules; workspace auto-cleaned |
> Feed selection inspired by [public-api-lists/public-api-lists](https://github.com/public-api-lists/public-api-lists) (Anti-Malware, Security, Geocoding, Government, Health, Open Data, Vehicle, Development).

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

extro_osint(query: "1HGCM82633A004352")
  → kind=:vin · NHTSA vPIC decode (make/model/year/plant)

extro_osint(query: "00:11:22:33:44:55")
  → kind=:mac · OUI vendor (maclookup / macvendors)

extro_osint(query: "W1AW")
  → kind=:callsign · Callook FCC ULS (trustee, class, grid)

extro_osint(query: "CVE-2021-44228")
  → kind=:cve · FIRST EPSS score + CISA KEV membership

extro_osint(query: "8.8.8.8", feeds: ["ipapi_is", "iplocate", "greynoise", "abuseipdb"])
  → multi-source IP threat/geo (keyed feeds skip cleanly when no key)

extro_osint(query: "@defunkt")
  → kind=:social · Keybase proofs + Bluesky DID + HN karma + npm/RubyGems/DockerHub + ~100-site sweep

extro_osint(query: "@gargron@mastodon.social")
  → kind=:social · Fediverse WebFinger + Mastodon profile

extro_osint(query: "defunkt", feeds: ["social_sweep"], limit: 50)
  → Sherlock-mode presence sweep only (107 sites, ~10-15 s @ 16 threads)

extro_osint(query: "target.tld", feeds: ["theharvester", "amass"])
  → local-tool bridges: passive subdomain + email harvest (skips cleanly if bins absent)
```

Configure:

```ruby
PWN::Env[:ai][:agent][:extrospection][:osint] = {
  ttl: 86_400,
  api_keys: {
    shodan: '...',
    hunter: '...',
    abuseipdb: '...',
    virustotal: '...',
    greynoise: '...',
    haveibeenpwned: '...',
    securitytrails: '...',
    steam: '...'
  },
  social: {
    sites_file: '/opt/pwn/etc/osint/social_sites.json',   # override / extend the vendored sherlock-derived list
    max_threads: 16,                                       # concurrent presence checks in :social_sweep
    max_sites: 120,                                        # cap sites read from sites_file
    timeout: 6,                                            # per-site HTTP timeout (seconds)
    mastodon_instance: 'mastodon.social'                   # default Fediverse instance for bare @handle
  },
  bridges: {
    timeout: 120,                                          # per-tool wall clock (seconds)
    theharvester_sources: 'anubis,crtsh,hackertarget,otx,rapiddns,urlscan,certspotter,dnsdumpster,duckduckgo',
    spiderfoot_modules: 'sfp_dnsresolve,sfp_crt,sfp_hackertarget,sfp_dnsdumpster,sfp_wayback,sfp_social',
    amass_passive: true                                    # false → active enum (touches target DNS)
  }
}
# ENV fallbacks also accepted:
#   SHODAN_API_KEY, HUNTER_API_KEY, ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY,
#   GREYNOISE_API_KEY, HIBP_API_KEY, SECURITYTRAILS_API_KEY, STEAM_API_KEY
```


## `extro_serial` - Serial sense organ

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

## `extro_telecomm` - SIP / VoIP / PSTN sense organ

Telecomm analogue of `extro_rf_tune`. Talks to a **running** BareSIP HTTP
control socket (never launches it). Actions:

| action | Effect |
|---|---|
| `:inventory` / `:status` | bins · SIP listen ports · BareSIP HTTP reachability · status text |
| `:dial` | require `target:` SIP URI or E.164 - **OPSEC: real call** |
| `:hangup` | hang up active call |

```ruby
PWN::Env[:ai][:agent][:extrospection][:telecomm] = {
  host: '127.0.0.1', port: 8000, ttl: 600
}
```

## `extro_packet` - Packet sense organ

Bounded L2/L3 sensing via `tshark` / `tcpdump` + pcap summarisation through
`PWN::Plugins::Packet` / tshark hierarchy & conversations:

| action | Effect |
|---|---|
| `:inventory` | ifaces + PACKET_BINS presence |
| `:capture` | short capture → `~/.pwn/extrospection/packet/*.pcap` + summary |
| `:summarize_pcap` | parse `path:` pcap (protocol hierarchy, IP conversations) |

Capture is hard-capped (`count` ≤ 200, `timeout` ≤ 60s) so the agent never
hangs mid-turn.

## `extro_vision` - Vision / OCR sense organ

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

## `extro_voice` - Voice (TTS / STT) sense organ

| action | Backend |
|---|---|
| `:tts` | espeak-ng → spd-say → festival (`PWN::Plugins::Voice`) |
| `:stt` | OpenAI whisper binary / `PWN::Plugins::Voice.speech_to_text` |
| `:inventory` | VOICE_BINS presence |

Artifacts land under `~/.pwn/extrospection/voice/`.

## `revalidate_memory` - the browser as GC for `PWN::Memory`


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
  anchors:          ['https://target.acme/api/version', ...],  # else DEFAULT_WEB_ANCHORS
  proxy:            'tor',      # or 'http://127.0.0.1:8080' (Burp) - honoured by verify/watch/probe_web
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
# ... recon ...
extro_observe(source: 'nmap', target: '10.0.0.5',
              category: 'recon', data: 'OpenSSH 8.2p1 Ubuntu')
extro_observe(source: 'gqrx', target: '433.920MHz',
              category: 'rf', data: 'peak -34.2 dBFS bw=200k FSK - likely garage remote')
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
# ... days later, something breaks ...
extro_drift                            # what moved?
extro_correlate                        # why did it break?
```

## Example questions that trigger Extrospection

Natural-language prompts that should route to **outward** sensing rather than
introspection. These are phrased the way an offensive security researcher
actually asks them mid-engagement - attack-surface discovery, zero-day
hunting, hardware/RF poking, and disclosure prep. Location-specific examples
use **Chicago** so the catalog stays portable.

### RF / SDR sense organ (`extro_rf_tune` + `:rf` observations)

- "Tune 433.92 MHz - is the target's garage/gate remote fixed-code or rolling?"
- "Sweep the 900 MHz ISM band near the badge reader and log anything > −40 dBFS."
- "What's broadcasting on 101.1 FM right now - grab RDS PI/PS so we can prove SDR is live."
- "Sample 868.3 MHz for 15 s - does the smart-meter mesh look like Wireless M-Bus?"
- "Any ADS-B traffic squawking over the client's campus (near ORD)?"
- "Listen on the pager band (929.x MHz) - are unencrypted POCSAG pages leaking PHI?"
- "Is the site's DMR/TETRA handheld traffic on 462.x actually encrypted?"
- "Park on 315 MHz and tell me if the target's TPMS / key-fob replays cleanly."

### Web / browser sense organ (`extro_watch`, `extro_verify`, `snapshot(sections: [:web])`)

- "Watch the target's `/api/version` endpoint - alert me the moment the build string changes."
- "Has the vendor silently patched? Diff today's changelog DOM against our last hash."
- "Did the bug-bounty scope page add or drop assets since we baselined it?"
- "Fingerprint the login portal's JS bundle - framework, version, source-map leakage."
- "Screenshot + DOM-hash the admin panel so we can prove pre-auth state for the report."
- "Render the CSP/`.well-known/security.txt` and tell me who to disclose to."
- "Has the target's TLS cert or issuer rotated since the last watch?"

### OSINT sense organ (`extro_osint`)

- "Enumerate every subdomain for `*.target.tld` via CT logs (crt.sh + CertSpotter)."
- "Who owns AS-XXXXX and what netblocks does it announce - expand our in-scope ranges."
- "Pull EPSS + CISA KEV for CVE-2024-3094 - is this worth weaponising first?"
- "What's Shodan / GreyNoise saying about `203.0.113.10` - already mass-exploited?"
- "Decode this VIN off the fleet vehicle - what telematics head-unit ships in that trim?"
- "FCC ID `2ABIP-...` on the IoT doorbell - pull the internal photos and RF test report."
- "MAC OUI `AC:DE:48` on the rogue AP - which vendor, and do they have default creds?"
- "Any prior litigation or SEC 8-K breach filings for `Target Corp` before we disclose?"
- "Wayback the old `/admin` path - did an earlier deploy expose a debug console?"
- "Pivot `@lead-dev` across GitHub/GitLab - hardcoded secrets in personal repos?"
- "Sweep `@lead-dev` across ~100 socials - which platforms reuse that handle, and does Keybase crypto-prove any of them?"
- "Gravatar `alice@target.tld` - what username, avatar and verified accounts leak from that email?"
- "Which npm / PyPI / RubyGems / DockerHub packages does `@maintainer` own - supply-chain blast radius?"
- "Run theHarvester + amass (passive) against `target.tld` and merge with our crt.sh subdomains."

### Serial / hardware sense organ (`extro_serial`)

- "What just enumerated on `/dev/ttyUSB*` when I plugged in the router's UART header?"
- "Send `AT+GMR` to the ESP32 on `/dev/ttyUSB0` - firmware version and SDK build?"
- "Dump the boot banner at 115200 8N1 - does it drop to an unauthenticated U-Boot shell?"
- "Probe the Flipper on `ttyACM0` and pull the last captured Sub-GHz raw."
- "Talk to the smart-lock's BLE-UART bridge and echo back whatever it volunteers."

### Telecomm / VoIP sense organ (`extro_telecomm`)

- "Is BareSIP registered to the client's PBX, and what codecs did it negotiate?"
- "Enumerate SIP `OPTIONS` against the exposed SBC - does it leak `User-Agent`/version?"
- "Dial the IVR at `sip:ivr@target` and record the prompt tree for the social-eng playbook." *(OPSEC: real call)*
- "Hang up and note whether the PBX exposed internal extension ranges in the `BYE`."

### Packet sense organ (`extro_packet`)

- "Capture 30 s on `eth0` while I trigger the IoT hub - what does it phone home to?"
- "Summarise `/tmp/eng.pcap` - top talkers, cleartext creds, weird ports."
- "BPF `udp port 5353` - is mDNS leaking hostnames and service records on the guest VLAN?"
- "Grab 50 packets of the OT segment - Modbus/TCP or something proprietary?"
- "Do we see the camera's RTSP creds in the clear during that capture?"

### Vision / OCR sense organ (`extro_vision`)

- "OCR the photo of the switch label - model, firmware, and default-cred sticker."
- "Decode the QR on the badge printer - is that a provisioning URL with an embedded token?"
- "OCR the BIOS/BMC screenshot and pull the exact firmware build for CVE matching."
- "Read the barcode on the HSM - serial + part number for supply-chain lookup."

### Voice sense organ (`extro_voice`)

- "Transcribe `/tmp/voicemail.wav` - did the helpdesk leak the temp-password format?"
- "STT the recorded IVR tree so we can grep it for extension numbers."
- "TTS this vishing pretext to a `.wav` for the approved social-engineering call."
- "Which STT/TTS engines are installed - can we run whisper offline on the drop box?"

### Fact-check / claim verification (`extro_verify`)

- "Before I file this: does CVE-2024-3094 actually list our target's distro package as affected?"
- "Confirm the latest upstream OpenSSH is 9.x - is the target's 8.2p1 genuinely EOL?"
- "Verify the vendor advisory URL really says 'remote unauthenticated' - quote it back."
- "Is `pwn` on RubyGems still at the version we ship in the report appendix?"
- "Fact-check my claim that this library has no maintained fork - search says otherwise?"

### Threat intel (`extro_intel` ± `record:true`)

- "Any public PoC or Exploit-DB entry for the exact `nginx 1.25.3` build we bannered?"
- "Pull NVD + CIRCL for `libwebp` since 2023 - which are pre-auth RCE vs local?"
- "Cross-ref this router's firmware components against known-exploited (KEV)."
- "What's the newest CVE touching `Fortinet FortiOS` and is there an exploit module yet?"
- "Record everything for `Apache Struts` so `extro_correlate` can match our target stack."

### Host / env / toolchain drift (`extro_snapshot`, `extro_drift`, `extro_stats`)

- "Snapshot the drop box before we start - I want a defensible 'this is what we brought' baseline."
- "Did anything on this attack host change overnight (kernel, nmap, listening ports)?"
- "Which offensive bins are actually present in PATH on this jump host?"
- "Is the SDR / HackRF still attached, or did the USB hub flake again?"
- "Show repo HEAD + dirty state so the finding is reproducible from a commit hash."

### Recon memory / observations (`extro_observe`, `extro_observations`)

- "Remember: `10.0.0.5:8443` self-signed CN leaks internal AD domain - tag `recon,pivot`."
- "Log the RF finding: 433.92 MHz fixed-code, 24-bit, replayable - tag `rf,physical`."
- "What have we already observed about `*.target.tld` this engagement?"
- "List every `:intel` observation still fresh so I don't re-run the same CVE queries."
- "Which `:web` watches flipped `changed:true` this week - silent patch candidates?"

### Correlation - "am I wrong or did the world move?" (`extro_correlate`)

- "My exploit stopped landing - did the target's DOM/TLS drift or did I break the payload?"
- "Cross recorded CVE intel against the versions we actually bannered on scope hosts."
- "Are any of my `PWN::Memory` facts about this target now refuted by fresh `extro_verify` runs?"
- "Do the `nmap`/`msf` failures line up with a toolchain upgrade rather than operator error?"
- "Which watched anchors went unreachable - down-weight intel sourced from them."

### Operational / lifecycle

- "New engagement, new client - wipe extrospection so old recon doesn't bleed into this report." *(destructive)*
- "Turn ambient auto-extrospect **off** while I fuzz - I don't want baseline noise per turn."
- "How stale is our world snapshot - is it still from the pre-patch window?"
- "Re-enable auto-extrospect for the wrap-up so drift is captured in the final deliverable."

### Short trigger patterns the agent should recognize

| Pattern | Likely tools |
|---|---|
| "tune / MHz / FM / RDS / ISM / key-fob / pager / ADS-B" | `extro_rf_tune` |
| "subdomain / CT log / ASN / whois / FCC ID / VIN / MAC OUI / EPSS / KEV / Wayback / pivot @user / Keybase / Gravatar / social sweep / theHarvester / amass" | `extro_osint` |
| "UART / ttyUSB / U-Boot / AT command / Flipper / JTAG banner" | `extro_serial` |
| "SIP / PBX / IVR / BareSIP / dial / hangup" | `extro_telecomm` |
| "capture on iface / summarise pcap / mDNS / Modbus / RTSP creds" | `extro_packet` |
| "OCR sticker / decode QR / read badge / BIOS screenshot" | `extro_vision` |
| "transcribe wav / TTS pretext / whisper offline" | `extro_voice` |
| "watch URL / did the page change / silent patch / scope updated / TLS rotated" | `extro_watch` |
| "is it true that / confirm CVE / verify advisory / latest version of" | `extro_verify` |
| "known exploits for / any PoC / CVEs affecting / KEV for" | `extro_intel` |
| "what changed on this host / baseline the box / SDR still attached" | `extro_snapshot` + `extro_drift` |
| "remember this finding / what did we observe about / tag it recon" | `extro_observe` / `extro_observations` |
| "why did X stop working / my fault or theirs / down-weight that source" | `extro_correlate` |
| "new engagement clean slate / stop baselining while I fuzz" | `extro_reset` / `extro_auto_toggle` |

The **inward** half of the loop (Memory · Skills · Learning · Mistakes · Metrics)
has a matching example catalog in
[Skills, Memory & Learning](Skills-Memory-Learning.md#example-questions-that-trigger-introspection).

**See also:** [Skills, Memory & Learning](Skills-Memory-Learning.md) ·
[Mistakes](Mistakes.md) · [SDR](SDR.md) · [Transparent Browser](Transparent-Browser.md) · [Cron](Cron.md) · [pwn-ai Agent](pwn-ai-Agent.md)

[← Home](Home.md)
