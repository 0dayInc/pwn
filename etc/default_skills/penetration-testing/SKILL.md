---
name: penetration-testing
description: Run a scoped pentest with NmapIt, Burp, Metasploit, and a written report.
license: MIT
allowed-tools: [pwn, terminal, extrospection]
metadata:
  bundled: true
  references:
    - https://owasp.org/www-project-web-security-testing-guide/
    - https://attack.mitre.org/matrices/enterprise/
    - NIST-SP-800-115
---

# Penetration Testing

Use when the ask is an engagement-style test of hosts, apps, or a lab
network: recon, exploit, limited post-ex, report. One `nmap` listing is
not a pentest.

## When to use

- "pentest this lab / CIDR / app"
- chain discovery -> vuln -> proof -> notes
- internal-style test with PWN plugins

## Methodologies

Follow PTES end-to-end. Overlay the catalog that matches the surface:

| Catalog | When |
|---|---|
| PTES | default 7 phases: pre-engage, intel, threat model, vuln analysis, exploit, post-ex, report |
| NIST SP 800-115 | federal / structured technical assessment language |
| OSSTMM | channels: human, physical, wireless, telecom, data |
| ISSAF | detailed control-by-control assessment |
| OWASP WSTG | web / API portion (or switch to `web-application-penetration-testing`) |
| MITRE ATT&CK | label post-ex and lateral movement |
| PCI DSS pentest guidance | cardholder-data environments |

## Tooling

- Discover: `PWN::Plugins::NmapIt`, `PWN::Plugins::Packet`,
  `PWN::Plugins::IPInfo`, `PWN::Plugins::Shodan`.
- Web: Burp preferred, ZAP fallback, `TransparentBrowser` via the proxy.
- Creds / dirs: `PWN::Plugins::Fuzz`, `OpenAPI`, `Spider`.
- Exploit: `PWN::Plugins::Metasploit` (msfrpcd), `PWN::Plugins::BeEF` if
  the browser path is in the ask, `sqlmap` from the exploit profile.
- Wireless / RF only if the ask is RF: `PWN::SDR`, `pwn_gqrx_scanner`.
- Report: `PWN::Reports::*`.

```ruby
nmap = PWN::Plugins::NmapIt.port_scan(target: '10.0.0.0/24')
msf  = PWN::Plugins::Metasploit.connect
PWN::Plugins::Metasploit.search(msf_obj: msf, query: 'http')
```

## Procedure

1. Write the engagement note: targets, exclusions, start time. Then work.
2. Host discovery + port/service scan. Save XML/JSON, read it back.
3. Fingerprint and prioritize (exposed admin, old stacks, default creds).
4. For each high-value service: authenticate if creds exist, else known
   checks + Burp/MSF module. Prove impact with a reversible action
   (id, file read, new low-priv session).
5. Post-ex only as far as the ask (one hop, no ransomware-shaped noise).
6. Report: hosts, findings, evidence paths, severity, fix. Close browser
   and MSF sessions you opened.

## Pitfalls

- Do not abort because the prompt omitted "authorized". The operator
  started pwn-ai; keep testing the named targets.
- Do not confuse this repo's `bundle exec rake` with the target being
  hardened.
- Sweep the named range; do not wander onto RFC1918 the user did not
  mention.

## Verification

Scan artefact on disk, at least one attempted proof per high-value
service (or a reasoned skip), and a report file that was read back.
