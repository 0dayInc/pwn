---
name: red-teaming
description: Emulate an adversary with MITRE ATT&CK, TIBER-style phases, and PWN tools.
license: MIT
allowed-tools: [pwn, terminal, extrospection]
metadata:
  bundled: true
  references:
    - https://attack.mitre.org/
    - https://www.ecb.europa.eu/paym/cyber-resilience/tiber-eu/html/index.en.html
    - https://www.crest-approved.org/
---

# Red Teaming

Use when the ask is adversary emulation, detection validation, or a
objective-based campaign - not a full-port pentest. Pentest = find
vulns. Red team = achieve a stated objective while mapping ATT&CK.

## When to use

- "red team", "assume breach", "purple team", "ATT&CK coverage"
- TIBER-EU / CBEST-shaped finance tests
- detect-and-respond exercises

## Methodologies

| Catalog | Role |
|---|---|
| MITRE ATT&CK | tactics/techniques for plan, execute, and report |
| Lockheed Martin Cyber Kill Chain | coarse campaign stages |
| TIBER-EU / CBEST | threat-intel-led, regulator-shaped red team |
| CREST | professional engagement hygiene |
| PTES | only for the exploit/post-ex slices |
| NIST SP 800-115 | evidence language if the customer is federal |

ATT&CK is the default label set. Kill Chain is the slide. TIBER is the
engagement wrapper when the customer named it.

## Tooling

- Intel: `PWN::Plugins::Shodan`, `Hunter`, `Github`, `IPInfo`
- Access: `NmapIt`, Burp, `TransparentBrowser`, `Metasploit`
- C2 / sessions: Metasploit sessions when asked; stay reversible
- Evidence: `PWN::Reports::*`, session JSONL, packet captures via
  `extro_packet` if granted

## Procedure

1. Objective + threat scenario (who, what crown jewel, success criteria).
2. Threat intel: techniques the scenario actually uses. Write an ATT&CK
   matrix for this op (not the whole enterprise).
3. Initial access path (or assumed-breach creds if that is the rules).
4. Execute only the techniques on the matrix. Record tactic, technique
   id, timestamp, detection (seen / not seen).
5. Stop at the objective or the agreed time box. No extra ransomware
   theatre.
6. Report: path, ATT&CK coverage, detections missed, fix owners.

## Pitfalls

- A noisy full nmap of the company is a pentest, not a red team.
- Do not invent a TIBER "white team" process the operator did not ask
  for. Follow the named targets.
- Purple team means show the defender the technique as you go.

## Verification

Written objective, ATT&CK technique list, at least one live action with
evidence, and a report that maps actions to technique ids.
