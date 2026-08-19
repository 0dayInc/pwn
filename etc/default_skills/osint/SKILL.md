---
name: osint
description: Drive extro_osint with the right kind, feeds, pivots, and keys.
license: MIT
allowed-tools: [pwn, terminal, extrospection]
metadata:
  bundled: true
  references:
    - https://attack.mitre.org/tactics/TA0043/
    - NIST-SP-800-115
---

# OSINT (extro_osint)

Use this whenever the ask is public-source intel on an IP, domain, email,
phone, handle, person, company, CVE, VIN, MAC, FCC ID, patent, or URL.
The verb is `extro_osint` (`PWN::AI::Agent::Extrospection.osint`). Do not
substitute `extro_snapshot(sections: [:osint])` - that only lists feed
availability. Do not scrape random sites when this organ already covers
the query.

## When to use

- reverse phone, person, @handle, company, CIK, NPI
- IP / ASN / BGP / Shodan / reputation
- domain CT / whois / RDAP / harvest
- CVE EPSS + CISA KEV
- VIN, MAC OUI, ham callsign, FCC ID, patent

Hand off live scanning to `penetration-testing` / `NmapIt`. Firmware IDs
can start here (`:fcc_id`) then `hardware-and-firmware-testing`.

## Methodologies

- MITRE ATT&CK TA0043 Reconnaissance (passive collection)
- NIST SP 800-115: target identification / OSINT as a technical technique
- OSSTMM data channel (passive only unless the operator named active DNS)

Stay passive by default. `amass` is passive unless
`ai.agent.extrospection.osint.bridges.amass_passive` is false.

## How to call

Prefer the tool:

```
extro_osint(query: "8.8.8.8")
extro_osint(query: "@defunkt", kind: "social")
extro_osint(query: "target.tld", feeds: ["dns", "crtsh", "theharvester"])
```

Or `pwn_eval`:

```ruby
PWN::AI::Agent::Extrospection.osint(query: '8.8.8.8', kind: :ip)
```

One atomic indicator per call. `kind: :auto` is fine when the string is
unambiguous. Force `kind:` when auto can steal the query (below).

## Force kind when auto is wrong

| Query looks like | Auto often picks | Force |
|---|---|---|
| IPv4 | `:ip` (ok) | - |
| `00:11:22:33:44:55` | `:mac` (ok; MAC beats IPv6) | - |
| 17-char VIN | `:vin` | - |
| `CVE-2021-44228` | `:cve` | - |
| `@user` / `@user@host` | `:social` | - |
| `a@b.c` | `:email` | - |
| `https://...` | `:url` | - |
| `NPI 1679576722` | `:npi` only with the `NPI` prefix | prefix or `kind: :npi` |
| `W1AW` | `:callsign` | - |
| bare `defunkt` | `:username` | `kind: :social` + `feeds: ["social_sweep"]` if presence is the ask |
| `Acme Robotics LLC` | `:company` | - |
| `birth record Jane Doe` | `:vital_records` | keep the keyword |
| `2ABIP-ESP32` | `:fcc_id` | `kind: :fcc_id` if no hyphen |
| 10-15 digits | `:phone` | E.164 `+1...` if possible |
| free text name | `:person` | `kind: :person` |

Do not pass a paragraph as `query`. Extract the indicator first.

## Pick feeds; do not boil the ocean

Default feeds-for-kind can be a dozen HTTP calls. Narrow when you know
the question:

| Question | feeds |
|---|---|
| Where is this IP / is it noisy? | `ipapi_is`, `iplocate`, `greynoise`, `abuseipdb` |
| What certs / names? | `crtsh`, `certspotter` |
| Passive domain harvest | `theharvester`, `amass` (bins; skip if absent) |
| Handle presence | `keybase`, `github`, `social_sweep` (`limit: 50`) |
| Company | `opencorporates`, `sec_edgar`, `courtlistener` |
| CVE worth exploiting? | `epss`, `cisa_kev` |
| Breach on email | `haveibeenpwned` (needs key) |

Read `results[:summary]` and per-feed `{skipped:}` / `{error:}`. A skipped
keyed feed is not a finding - it means no key.

## Keys (vault or ENV)

Set under `ai.agent.extrospection.osint.api_keys.*` or ENV. Missing key
returns `{skipped:}` and the rest of the call still runs.

| Feed | ENV |
|---|---|
| shodan | `SHODAN_API_KEY` |
| hunter | `HUNTER_API_KEY` |
| abuseipdb | `ABUSEIPDB_API_KEY` |
| virustotal | `VIRUSTOTAL_API_KEY` / `VT_API_KEY` |
| greynoise | `GREYNOISE_API_KEY` |
| haveibeenpwned | `HIBP_API_KEY` |
| securitytrails | `SECURITYTRAILS_API_KEY` |
| steam | `STEAM_API_KEY` |

If several keyed feeds skip, say which keys are missing. Do not invent
Shodan banners.

## Pivot loop

1. First call: one indicator, auto or forced kind, default or tight feeds.
2. From `summary`, pull the next indicator (domain from cert, email from
   hunter, @handle from keybase, ASN from bgpview).
3. Second call on that indicator. Tag the chain in the answer.
4. `record` defaults true (`observe(category: :osint)`). Later
   `extro_observations(category: :osint)` instead of repeating the same
   query in-session.
5. Stop when the original ask is evidenced (who / where / exposure), not
   after one feed listing.

## Pitfalls

- `extro_snapshot(sections: [:osint])` is inventory. It does not look up
  the target.
- `social_sweep` is soft-404 prone (confidence <= 0.5). Confirm hits.
- `theharvester` / `amass` / `spiderfoot` / `reconng` no-op without the
  local bin. Install via `pwn setup --profile net` or skip those feeds.
- Active amass touches target DNS. Leave passive unless asked.
- Default `limit` is 5. Raise only for sweep/harvest.
- Do not treat `{error:}` on one feed as a failed OSINT pass.

## Verification

`results[:kind]` matches the indicator, at least one feed returned data
(not only skips), and the answer cites that summary. If every useful feed
skipped, the artefact is the missing-key list plus any public-feed hits.
